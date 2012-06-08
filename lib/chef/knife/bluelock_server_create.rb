#
# Author:: Chirag Jog (<chiragj@websym.com>)
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

require 'highline'
require 'net/ssh/multi'
require 'readline'
require 'net/scp'
require 'chef/knife'
require 'tempfile'

class Chef
  class Knife
    class BluelockServerCreate < Knife

      deps do
        require 'fog'
        require 'readline'
        require 'chef/json_compat'
        require 'chef/knife/bootstrap'
        Chef::Knife::Bootstrap.load_deps
      end

      banner "knife bluelock server create NAME [RUN LIST...] (options)"

      option :bluelock_password,
        :short => "-K PASSWORD",
        :long => "--bluelock-password PASSWORD",
        :description => "Your Bluelock password",
        :proc => Proc.new { |key| Chef::Config[:knife][:bluelock_password] = key }

      option :bluelock_username,
        :short => "-A USERNAME",
        :long => "--bluelock-username USERNAME",
        :description => "Your Bluelock username",
        :proc => Proc.new { |username| Chef::Config[:knife][:bluelock_username] = username } 


      option :run_list,
        :short => "-r RUN_LIST",
        :long => "--run-list RUN_LIST",
        :description => "Comma separated list of roles/recipes to apply",
        :proc => lambda { |o| o.split(/[\s,]+/) },
        :default => []

      option :distro,
        :short => "-d DISTRO",
        :long => "--distro DISTRO",
        :description => "Bootstrap a distro using a template; default is 'ubuntu10.04-gems'",
        :proc => Proc.new { |d| Chef::Config[:knife][:distro] = d },
        :default => "ubuntu10.04-gems"

      option :template_file,
        :long => "--template-file TEMPLATE",
        :description => "Full path to location of template to use",
        :proc => Proc.new { |t| Chef::Config[:knife][:template_file] = t },
        :default => false

      option :chef_node_name,
        :short => "-N NAME",
        :long => "--node-name NAME",
        :description => "The Chef node name for your new node",
        :proc => Proc.new { |t| Chef::Config[:knife][:chef_node_name] = t }

      option :enable_firewall,
        :long => "--enable-firewall",
        :description => "Install a Firewall to control public network access",
        :boolean => true,
        :default => false

      option :tcp_ports,
        :short => "-T X,Y,Z",
        :long => "--tcp X,Y,Z",
        :description => "TCP ports to be made accessible for this server",
        :proc => Proc.new { |tcp| tcp.split(',') },
        :default => ["22"]

      option :udp_ports,
        :short => "-U X,Y,Z",
        :long => "--udp X,Y,Z",
        :description => "UDP ports to be made accessible for this server",
        :proc => Proc.new { |udp| udp.split(',') },
        :default => []

      option :server_name,
        :short => "-N NAME",
        :long => "--server-name NAME",
        :description => "The server name",
        :proc => Proc.new { |server_name| Chef::Config[:knife][:server_name] = server_name } 

      option :image,
        :short => "-I IMAGE",
        :long => "--bluelock-image IMAGE",
        :description => "Your Bluelock virtual app template/image name",
        :proc => Proc.new { |template| Chef::Config[:knife][:image] = template }

      option :vcpus,
        :long => "--vcpu VCPUS",
        :description => "Defines the number of vCPUS per VM. Possible values are 1,2,4,8",
        :proc => Proc.new { |vcpu| Chef::Config[:knife][:vcpus] = vcpu }

      option :memory,
        :short => "-m MEMORY",
        :long => "--memory MEMORY",
        :description => "Defines the number of MB of memory. Possible values are 512,1024,1536,2048,4096,8192,12288 or 16384.",
        :proc => Proc.new { |memory| Chef::Config[:knife][:memory] = memory }

      option :ssh_password,
          :short => "-p PASSWORD",
          :long => "--password PASSWORD",
          :description => "SSH Password for the user",
          :proc => Proc.new { |password| Chef::Config[:knife][:ssh_password] = password }

      def h
        @highline ||= HighLine.new
      end
      
      def locate_config_value(key)
        key = key.to_sym
        Chef::Config[:knife][key] || config[key]
      end

      def tcp_test_ssh(hostname, port)
        tcp_socket = TCPSocket.new(hostname, port)
        readable = IO.select([tcp_socket], nil, nil, 5)
        if readable
          Chef::Log.debug("sshd accepting connections on #{hostname}, banner is #{tcp_socket.gets}")
          yield
          true
        else
          false
        end
      rescue Errno::ETIMEDOUT
        false
      rescue Errno::EPERM
        false
      rescue Errno::ECONNREFUSED
        sleep 2
        false
      rescue Errno::EHOSTUNREACH
        sleep 2
        false
     rescue Errno::ENETUNREACH
        sleep 2
        false
     rescue Errno::ECONNRESET
        sleep 2
        false 
      ensure
        tcp_socket && tcp_socket.close
      end

      def run

        $stdout.sync = true
        unless Chef::Config[:knife][:server_name]
          ui.error("Server Name cannot be empty")
          exit 1
        end

	    unless Chef::Config[:knife][:bluelock_username] && Chef::Config[:knife][:bluelock_password]
	      ui.error("Missing Credentials")
	      exit 1
	    end
        server_name = Chef::Config[:knife][:server_name]
        vapp_template = Chef::Config[:knife][:image]
        key_name = Chef::Config[:knife][:ssh_key_name]
        vcloud = Fog::Vcloud::Compute.new(
            :vcloud_username => Chef::Config[:knife][:bluelock_username],
            :vcloud_password => Chef::Config[:knife][:bluelock_password],
            :vcloud_host => 'zone01.bluelock.com',
            :vcloud_version => '1.5'
        )

        vcpus = Chef::Config[:knife][:vcpus]
        memory = Chef::Config[:knife][:memory]
        password = Chef::Config[:knife][:ssh_password]
    
        image = Chef::Config[:knife][:image]
        server_spec = {
            :name =>  Chef::Config[:knife][:server_name], 
            :catalog_item_uri => nil
        }
        catalog = vcloud.catalogs.each do |catalog| 
            catalog_items = catalog.catalog_items
            catalog = catalog_items.find{|catalog_item| catalog_item.href.scan(image).size > 0 }
            if catalog
                server_spec[:catalog_item_uri] = catalog.href
                break
            end
        end

        if server_spec[:catalog_item_uri].nil?
            ui.error("Cannot find Image in the Catalog: #{image}")
            exit 1
        end
        vapp = vcloud.servers.create(server_spec)
        print "Instantiating Server(vApp) named #{h.color(vapp.name, :bold)} with id #{h.color(vapp.href.split('/').last.to_s, :bold)}"
        print "\n#{ui.color("Waiting for server to be Instantiated", :magenta)}"

        # wait for it to be ready to do stuff
        vapp.wait_for { print "."; ready? }
        puts("\n")
        vapp = vcloud.get_vapp(vapp.href)
        server = vcloud.get_server(vapp.children[:href])
        print "\n#{ui.color("Configuring the server as required", :magenta)}"
        if not vcpus.nil?
          server.cpus
          server.cpus = vcpus
          server.save
        end

        if not memory.nil?
          server.memory
          server.memory = memory
          server.save
        end

        if not password.nil?
          server.password
          server.password = password
          server.save
        end

        # NAT 
        vapp = server.vapp 
        vapp_network = vapp.network_configs[:NetworkConfig][:networkName]
        vapp_network_uri =vapp.network_configs[:NetworkConfig][:Link][:href]
        org_network = vcloud.networks.all.find{|net| not net.name.scan("internet").empty? }

        enable_firewall=false
        portmap=nil

        if config[:enable_firewall]
          print "\n#{ui.color("Enable Internet Access for SSH and other services", :magenta)}"
          tcp_ports = config[:tcp_ports] + ["22"] # Ensure we always open the SSH Port
          udp_ports = config[:udp_ports]

          services_spec = {"TCP" => tcp_ports.uniq, "UDP" => udp_ports.uniq}
          enable_firewall=true
          portmap=services_spec
        end

        vcloud.configure_org_network(vapp.href, 
                                         vapp_network, 
                                         vapp_network_uri, 
                                         org_network.name, 
                                         org_network.href, 
                                         enable_firewall=enable_firewall,
                                         portmap=portmap)

        # wait for it to be configure to do stuff
        server.wait_for { print "."; ready? }
        puts("\n")

        #Power On the server
        server.power_on
        print "\n#{ui.color("Waiting for server to be Powered On", :magenta)}"
        server.wait_for { print "."; on? }
        puts("\n")
        public_ip_address = server.network_connections[:ExternalIpAddress]
        private_ip_address = server.network_connections[:IpAddress] 
        puts "#{ui.color("Server Public IP Address", :cyan)}: #{public_ip_address}"
        puts "#{ui.color("Server Private IP Address", :cyan)}: #{private_ip_address}"
        puts "#{ui.color("Server Password", :cyan)}: #{server.password}"
        print "\n#{ui.color("Waiting for sshd.", :magenta)}"
        puts("\n")
        print(".") until tcp_test_ssh(public_ip_address, "22") { sleep @initial_sleep_delay ||= 10; puts("done") }
        puts "\nBootstrapping #{h.color(server_name, :bold)}..."
        bootstrap_for_node(server).run
      end

      def bootstrap_for_node(server)
        bootstrap = Chef::Knife::Bootstrap.new
        bootstrap.name_args = [server.network_connections[:ExternalIpAddress]]
        bootstrap.config[:run_list] = config[:run_list]
        bootstrap.config[:ssh_user] = "root"
        bootstrap.config[:ssh_password] = server.password
        bootstrap.config[:chef_node_name] = locate_config_value(:chef_node_name) || server.name
        bootstrap.config[:distro] = locate_config_value(:distro)
        bootstrap.config[:bootstrap_version] = locate_config_value(:bootstrap_version)
        bootstrap.config[:use_sudo] = true unless config[:ssh_user] == 'root'
        bootstrap.config[:template_file] = locate_config_value(:template_file)
        bootstrap
      end
    end
  end
end
