# encoding: utf-8
# frozen_string_literal: true

# copyright: 2016, Christoph Hartmann
# license: MPLv2
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

require 'json'

# represents the object for one windows update
class WindowsUpdate
  def initialize(data)
    @data = data
  end

  def title
    @data['Title']
  end

  # https://msdn.microsoft.com/en-us/library/windows/desktop/aa386906(v=vs.85).aspx
  def criticality
    case @data['MsrcSeverity']
    when 'Critical'
      1.0
    when 'Important'
      0.7
    when 'Moderate'
      0.5
    when 'Low'
      0.3
    else
      0.0
    end
  end

  def installed?
    false
  end

  def to_s
    "Windows Update '#{title}'"
  end
end

class WindowsUpdateManager < Inspec.resource(1)
  name 'windows_update'
  desc 'Use the windows_update InSpec audit resource to test available or installed updates on Microsoft Windows.'

  def initialize # rubocop:disable_block Lint/ReturnInVoidContext
    super()
    # verify that this resource is only supported on Windows
    return skip_resource 'The `windows_update` resource is not supported on your OS.' unless inspec.os.windows?

    @update_mgmt = select_update_mgmt
  end

  # returns all available updates
  def all
    updates = fetch_updates
    updates.map { |update| WindowsUpdate.new(update) }
  end

  # returns all important updates
  def important
    updates = fetch_updates
    updates
      .select do |update|
        @update_mgmt.important?(update)
      end.map do |update| # rubocop:disable Style/MultilineBlockChain
        WindowsUpdate.new(update)
      end
  end

  # returns all optional updates
  def optional
    updates = fetch_updates
    updates.select do |update|
      @update_mgmt.optional?(update)
    end.map do |update| # rubocop:disable Style/MultilineBlockChain
      WindowsUpdate.new(update)
    end
  end

  def reboot_required?
    return @reboot_required if defined?(@reboot_required)

    @reboot_required = inspec.registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update').has_property?('RebootRequired')
  end

  def to_s
    'Windows Update Services'
  end

  # private

  # detection for nano server
  # @see https://msdn.microsoft.com/en-us/library/hh846315(v=vs.85).aspx
  def windows_nano?
    return false unless inspec.os[:release].to_i >= 10

    inspec.powershell('Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels" | Select -ExpandProperty "NanoServer" ').stdout.chomp == '1'
  end

  private

  def select_update_mgmt
    if windows_nano?
      WindowsNanoUpdateFetcher.new(inspec)
    else
      Windows2012UpdateFetcher.new(inspec)
    end
  end

  def fetch_updates
    return [] if @update_mgmt.nil?

    @update_mgmt.fetch_updates
  end

  def hotfixes
    return [] if @update_mgmt.nil?

    @update_mgmt.hotfixes
  end
end

class UpdateFetcher
  def initialize(inspec)
    @inspec = inspec
  end

  def hotfixes
    []
  end

  def fetch_updates
    []
  end
end

class Windows2012UpdateFetcher < UpdateFetcher
  def hotfixes
    return @cache_hotfix_installed if defined?(@cache_hotfix_installed)

    hotfix_cmd = 'Get-HotFix | Select-Object -Property Status, Description, HotFixId, Caption, InstallDate, InstalledBy | ConvertTo-Json'
    cmd = @inspec.command(hotfix_cmd)
    begin
      @cache_hotfix_installed = JSON.parse(cmd.stdout)
    rescue JSON::ParserError => _e
      []
    end
  end

  def fetch_updates
    return @cache_available if defined?(@cache_available)

    script = <<-SCR
  $updateSession = new-object -com "Microsoft.Update.Session"
  $searcher=$updateSession.CreateupdateSearcher().Search(("IsInstalled=0 and Type='Software'"))
  $updates = $searcher.Updates | ForEach-Object {
    $update = $_
    $value = New-Object psobject -Property @{
      "UpdateID" =  $update.Identity.UpdateID;
      "RevisionNumber" =  $update.Identity.RevisionNumber;
      "CategoryIDs" = $update.Categories | % { $_.CategoryID }
      "Title" = $update.Title
      "SecurityBulletinIDs" = $update.SecurityBulletinIDs
      "RebootRequired" = $update.RebootRequired
      "KBArticleIDs" = $update.KBArticleIDs
      "CveIDs" = $update.CveIDs
      "MsrcSeverity" = $update.MsrcSeverity
    }
    $value
  }
  $updates | ConvertTo-Json
    SCR
    cmd = @inspec.powershell(script)

    begin
      result = JSON.parse(cmd.stdout)

      # PowerShell's `ConvertTo-Json` returns an Array of Hashes only if there
      # is more than one object passed into it, otherwise it returns a single
      # Hash. The below ensures that an Array is always returned regardless.
      @cache_available = result.is_a?(Array) ? result : [result]
    rescue JSON::ParserError => _e
      # Return `{}` if parsing fails to indicate that we couldn't retrieve data
      @cache_available = {}
    end
  end

  def important?(update)
    security_category?(update['CategoryIDs'])
  end

  def optional?(update)
    !important?(update)
  end

  # @see: https://msdn.microsoft.com/en-us/library/ff357803(v=vs.85).aspx
  # e6cf1350-c01b-414d-a61f-263d14d133b4 -> Critical Updates
  # 0fa1201d-4330-4fa8-8ae9-b877473b6441 -> Security Updates
  # 28bc880e-0592-4cbf-8f95-c79b17911d5f -> Update Rollups
  # does not include recommended updates yet
  def security_category?(uuids)
    return if uuids.nil?

    uuids.include?('0fa1201d-4330-4fa8-8ae9-b877473b6441') ||
      uuids.include?('28bc880e-0592-4cbf-8f95-c79b17911d5f') ||
      uuids.include?('e6cf1350-c01b-414d-a61f-263d14d133b4')
  end
end

class WindowsNanoUpdateFetcher < UpdateFetcher
  def fetch_updates
    return @cache_available if defined?(@cache_available)

    script = <<-SCR
  $sess = New-CimInstance -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession
  $scanResults = Invoke-CimMethod -InputObject $sess -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0";OnlineScan=$true}
  $updates = $scanResults.Updates | ForEach-Object {
    $update = $_
    $value = New-Object psobject -Property @{
      "UpdateID" =  $update.UpdateID;
      "RevisionNumber" =  $update.RevisionNumber;
      "Title" = $update.Title
      "MsrcSeverity" = $update.MsrcSeverity
    }
    $value
  }
  $updates | ConvertTo-Json
    SCR
    cmd = @inspec.powershell(script)

    begin
      result = JSON.parse(cmd.stdout)

      # PowerShell's `ConvertTo-Json` returns an Array of Hashes only if there
      # is more than one object passed into it, otherwise it returns a single
      # Hash. The below ensures that an Array is always returned regardless.
      @cache_available = result.is_a?(Array) ? result : [result]
    rescue JSON::ParserError => _e
      # Return `{}` if parsing fails to indicate that we couldn't retrieve data
      @cache_available = {}
    end
  end

  def important?(update)
    %w[Important Critical].include? update['MsrcSeverity']
  end

  def optional?(update)
    !important?(update)
  end
end
