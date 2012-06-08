#
# Author:: Adam Jacob (<adam@opscode.com>)
# Copyright:: Copyright (c) 2009 Opscode, Inc.
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
    class BluelockServerList < Knife

      banner "knife bluelock server list (options)"

      option :bluelock_password,
        :short => "-K PASSWORD",
        :long => "--bluelock-password PASSWORD",
        :description => "Your Bluelock password",
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

        server_list = [
            h.color('ID', :bold), 
            h.color('Name', :bold),
            h.color('Password', :bold),
            h.color('PublicIP', :bold),
            h.color('PrivateIP', :bold),
            h.color('OperatingSystem', :bold)
        
        ]
        vapps = bluelock.vapps.all
        for vapp in vapps
          vapp.servers.all.each do |server|
            server_list << vapp.href.split('/').last
            server_list << vapp.name.to_s
            server_list << server.password.to_s
            server_list << server.network_connections[:ExternalIpAddress].to_s
            server_list << server.network_connections[:IpAddress].to_s
            server_list << server.operating_system[:"ovf:Description"].to_s
          end
        end
        puts h.list(server_list, :columns_across, 5)

      end
    end
  end
end
