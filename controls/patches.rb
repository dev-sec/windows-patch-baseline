# encoding: utf-8
# copyright: 2016, Christoph Hartmann
# license: MPLv2
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

wu = windows_update

control 'verify-kb' do
  impact 1.0
  title "All updates should be installed"
  describe wu.all.length do
    it { should eq 0}
  end
end

control 'verify-important' do
  impact 1.0
  title "All important updates are installed"
  describe wu.important.length do
    it { should eq 0}
  end
end

control 'verify-optional' do
  impact 0.3
  title "All optional updates are installed"
  describe wu.optional.length do
    it { should eq 0}
  end
end

wu.important.each { |update|
  control "#{ update.title }" do
    impact update.criticality
    describe update do
      it { should be_installed }
    end
  end
}

wu.optional.each { |update|
  control "#{ update.title }" do
    impact update.criticality
    describe update do
      it { should be_installed }
    end
  end
}
