# encoding: utf-8
# copyright: 2016, Christoph Hartmann
# license: MPLv2
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

module Inspec::Resources

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
      return false
    end

    def to_s
      "Windows Update '#{title}'"
    end
  end

  class WindowsUpdateManager < Inspec.resource(1)
    name 'windows_update'
    desc 'Use the windows_update InSpec audit resource to test available or installed updates on Microsoft Windows.'

    def initialize
      # verify that this resource is only supported on Windows
      return skip_resource 'The `windows_update` resource is not supported on your OS.' if inspec.os[:family] != 'windows'
    end

    # returns all available updates
    def all
      updates = fetchUpdates
      updates.map { |update| WindowsUpdate.new(update) }
    end

    # returns all important updates
    def important
      # https://msdn.microsoft.com/en-us/library/ff357803(v=vs.85).aspx
      # e6cf1350-c01b-414d-a61f-263d14d133b4 -> Critical Updates
      # 0fa1201d-4330-4fa8-8ae9-b877473b6441 -> Security Updates
      # 28bc880e-0592-4cbf-8f95-c79b17911d5f -> Update Rollups

      updates = fetchUpdates
      updates
        .select { |update|
          isSecurityCategory(update['CategoryIDs'])
        }
        .map { |update| WindowsUpdate.new(update) }
    end

    # returns all optional updates
    def optional
      updates = fetchUpdates
      updates
        .select { |update|
          !isSecurityCategory(update['CategoryIDs'])
        }
        .map { |update| WindowsUpdate.new(update) }
    end

    # returns all installed hotfixes
    def hotfixes
      return @cache_hotfix_installed if defined?(@cache_hotfix_installed)

      hotfix_cmd = "Get-HotFix | Select-Object -Property Status, Description, HotFixId, Caption, InstallDate, InstalledBy | ConvertTo-Json"
      cmd = inspec.command(hotfix_cmd)
      begin
        @cache_hotfix_installed = JSON.parse(cmd.stdout)
      rescue JSON::ParserError => _e
        return []
      end
    end

    def reboot_required?
      return @chache_reboot if defined?(@chache_reboot)
      @chache_reboot = inspec.registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update').has_property?('RebootRequired')
    end

    def to_s
      "Windows Update Services"
    end

    private

    def isSecurityCategory(uuids)
      uuids.include?('0fa1201d-4330-4fa8-8ae9-b877473b6441') ||
      uuids.include?('28bc880e-0592-4cbf-8f95-c79b17911d5f') ||
      uuids.include?('e6cf1350-c01b-414d-a61f-263d14d133b4')
    end

    def fetchUpdates
      return @cache_available if defined?(@cache_available)
      script = <<-EOH
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
      EOH
      cmd = inspec.powershell(script)

      begin
        @cache_available = JSON.parse(cmd.stdout)
      rescue JSON::ParserError => _e
        # we return nil if an error occured to indicate, that we were not able to retrieve data
        @cache_available = {}
      end
    end
  end
end
