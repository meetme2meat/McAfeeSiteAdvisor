require "rubygems"
require "net/http"
require "net/https"
require "uri"
require "domainatrix"
require "hpricot"


module McAfee
  class McafeeSiteAdvisor
    URL = "http://dss1.siteadvisor.com"
    def self.report(*args)
      unsafe?(args)
    end
   
    def self.description(*args)
      call2mcafee(args,true)
    end
   
    def self.metadata(*args)
      call2mcafee(args,true,true)
    end
   
    def self.malformed?(url)
      begin
        URI.parse(url) || Domainatrix.parse(url)
        return false
      rescue => e
        return true
      end  
    end
    
    def self.domain(url)
      Domainatrix.parse(url).host
    end
    
   private
    def self.unsafe?(args)
      call2mcafee(args)
    end
    
    def self.call2mcafee(urls,description=false,metainfo=false)
      begin
        uri = URI.parse "#{URL}"
        raise "Cant Accept More than 10 urls at max" if urls.compact.count > 10
        path = "/DSS/MultiQuery?Type=domain&version=2&client_type=IEPlugin&client_ver=2.9.258&aff_id=0&locale=en-US"
        urls.each_with_index do |url,index|
          raise "#{url} is found be Malformed!!" if malformed?(url)
          path.concat("&Name_#{index+1}=#{domain(url)}")   
        end
      
        http = Net::HTTP.new(uri.host,uri.port) 
        result = Array.new
        xml_content = Hpricot.parse(http.get(path).body)
        classifications = xml_content.get_elements_by_tag_name('classification') 
          classifications.each_with_index do |classify, index| 
            metainfo ? result.push({"status" => safe_or_unsafe(classify),"description" => classify.get_elements_by_tag_name('description').text}) : (description ? result.push(classify.get_elements_by_tag_name('description').text) : result.push(safe_or_unsafe(classify))) 
          end
        return result
      rescue => e
        puts "Error Occurred  => #{e}"
        exit
      end
    end
    
    def self.safe_or_unsafe(classify)
      return (classify.get_attribute('color') == 'red') ?  "unsafe" :  "safe"
    end
    
  end
end




