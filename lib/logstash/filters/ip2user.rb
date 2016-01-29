# Call this file 'foo.rb' (in logstash/filters, as above)
require "logstash/filters/base"
require "logstash/namespace"
  $ipv4 = Hash.new
  $ipv6 = Hash.new

class LogStash::Filters::Ip2user < LogStash::Filters::Base
  #mesture a success of ip mapping user process (print to /dev/shm/mapping_counter) 
  @@mapping_counter=0
  #$ipv6 = Hash.new
  # Setting the config_name here is required. This is how you
  # configure this filter from your logstash config.
  #
  # filter {
  #   foo { ... }
  # }
  config_name "ip2user"

  # New plugins should start life at milestone 1.
  milestone 1

  # Replace the message with this value.
  config :message, :validate => :string

  public
  def register
    # nothing to do
  end # def register

  public
  def filter(event)
    # return nothing unless there's an actual filter event
    return unless filter?(event)
   #   system("echo \"enter ip2user plugin\"")
    if event["userStatus"] and event["userID"] and event["program"] == "Firewall-Auth" 
   #   system("echo \"enter ip2user=>check userStatus,userID,program\"")
      #check ipv4 parameter is exist?
      if event["userIPv4"] and event["userIPv4"] != "-"  
        if event["userStatus"] == "allow"
          $ipv4[event["userIPv4"]]=event["userID"]
        elsif event["userStatus"] == "remove" 
          $ipv4.delete(event["userIPv4"])
        end
 #       event["ip2userv4_size"] = $ipv4.length
      end 
      #check ipv6 parameter is exist?
      if event["userIPv6"] and event["userIPv6"] != "-"
        if event["userStatus"] == "allow"
          $ipv6[event["userIPv6"]]=event["userID"]
        elsif event["userStatus"] == "remove"
          $ipv6.delete(event["userIPv6"])
        end
 #       event["ip2userv6_size"] = $ipv6.length 
      end
      ipaddress_status="ipv4.length #{$ipv4.length}\nipv6.length #{$ipv6.length}"
  #    system("echo \"#{ipaddress_status}\" > \/dev\/shm\/logstash_ip")
    end


    if ! event["userID"] and event["userIPv4"] and event['userIPv4'] != "-" and $ipv4[event["userIPv4"]]
       event["userID"] = $ipv4[event["userIPv4"]]
#	@@mapping_counter+=1	
   #    system("echo \"#{@@mapping_counter}\">/dev/shm/mapping_counter")
   #    system("echo \"evnet mapping ip complete #{event["userID"]}<=>#{event['userIPv4']}\"")
    end
    #if @message
      # Replace the event message with our message as configured in the
      # config file.
    #  event["message"] = @message
    #end
    # filter_matched should go in the last line of our successful code 
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Foo
