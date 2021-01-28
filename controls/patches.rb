# encoding: utf-8
# frozen_string_literal: true

# copyright: 2016, Christoph Hartmann
# license: MPLv2
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# cache result set
win_update = windows_update

control 'verify-kb' do
  impact 0.3
  title 'All updates should be installed'
  describe win_update.all.length do
    it { should eq 0 }
  end
end

control 'important-count' do
  impact 1.0
  title 'No important updates should be available'
  describe win_update.important.length do
    it { should eq 0 }
  end
end

control 'important-patches' do
  impact 1.0
  title 'All important updates are installed'
  win_update.important.each do |update|
    describe update do
      it { should be_installed }
    end
  end
end

control 'optional-count' do
  impact 0.3
  title 'No optional updates should be available'
  describe win_update.optional.length do
    it { should eq 0 }
  end
end

control 'optional-patches' do
  impact 0.3
  title 'All optional updates are installed'
  win_update.optional.each do |update|
    describe update do
      it { should be_installed }
    end
  end
end
