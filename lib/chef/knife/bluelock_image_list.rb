#
# Author:: Adam Jacob (<adam@opscode.com>)
# Copyright:: Copyright (c) 2012 Opscode, Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'fog'
require 'highline'
require 'chef/knife'
require 'chef/json_compat'
require 'tempfile'

class Chef
  class Knife
    class BluelockImageList < Knife

      banner "knife bluelock image list (options)"

      option :bluelock_password,
        :short => "-K PASSWORD",
        :long => "--bluelock-password PASSWORD",
        :description => "Your bluelock password",
        :proc => Proc.new { |key| Chef::Config[:knife][:bluelock_password] = key } 

      option :bluelock_username,
        :short => "-A USERNAME",
        :long => "--bluelock-username USERNAME",
        :description => "Your bluelock username",
        :proc => Proc.new { |username| Chef::Config[:knife][:bluelock_username] = username } 


      def h
        @highline ||= HighLine.new
      end

      def run 
	unless Chef::Config[:knife][:bluelock_username] && Chef::Config[:knife][:bluelock_password]
	  ui.error("Missing Credentials")
	  exit 1
	end

        bluelock = Fog::Vcloud::Compute.new(
          :vcloud_username => Chef::Config[:knife][:bluelock_username],
          :vcloud_password => Chef::Config[:knife][:bluelock_password],
          :vcloud_host => 'zone01.bluelock.com',
          :vcloud_version => '1.5'
        )

        $stdout.sync = true

        images_list = [ h.color('ID', :bold), h.color('Name', :bold), h.color('Type', :bold) ]
        bluelock.catalogs.all.each do |catalog|
          catalog.catalog_items.all.each do |catalog_item|
            images_list << catalog_item.href
            images_list << catalog_item.name
            images_list << catalog.name
          end
        end
        puts h.list(images_list, :columns_across, 3)

      end
    end
  end
end


