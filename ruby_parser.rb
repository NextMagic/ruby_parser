require 'nokogiri'
require 'open-uri'

doc = File.open("CGHCAYLIFE.mbsa.log") { |f| Nokogiri::XML(f) }
puts doc.xpath("//UpdateData[@IsInstalled='false'][@Severity>=2]")
