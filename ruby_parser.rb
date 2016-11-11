# -*- coding: UTF-8 -*-
require 'nokogiri'
require 'open-uri'
require "csv"

def filter_garbled(string)
  whitelist = []
  string.each do |line|
    if line.each_byte.first  < 122 then
      whitelist << line
    end
  end
  return whitelist.join
end
def get_java(string)
  javaversion = string.scan(/FullVersion.*\W+REG_SZ\W+([\d\.\_\A-Za-z]+)/)
  return  javaversion.join
end
def get_iplist(string)
  ip_list = string.scan(/.*:\W+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/)
  return ip_list
end
def get_flash(string)
  flash_version = string.scan(/CurrentVersion.*\W+REG_SZ\W+([\d\.\_\A-Za-z\,]+)/)
  return flash_version.join
end
def get_adobe(string)
  adobe_version = string.scan(/ProductName.*\W+REG_SZ\W+(Adobe Reader[\d\.\ \_\A-Za-z\-]+)/)
  return adobe_version.join
end
def get_mbsa(xml,string)
  kblist = []
  xml.xpath(string).each do |f|
    #puts "#{f_windows.attributes['Name']}"
    f.xpath("./Detail/UpdateData[@IsInstalled='false'][@Severity>=4]").each do |f_update|
      kblist << "KB#{f_update.attributes['KBID']}"
    end
  end
  return kblist
end
def get_antipattern(string)
  anti_pattern_Non  = string.match(/InternalNonCrcPatternVer\W+REG_DWORD\W+(0x[\da-z]+)/)
  #anti_pattern = string.match(/InternalPatternVer\W+REG_DWORD\W+(0x[\da-z]+)/)
  if  anti_pattern_Non != nil then
    return anti_pattern_Non[1]
  else
    return 'Unstall'
  end
end
  CSV.open("resule.csv", "wb") do |csv|
  csv << ["HOST Name", "Windows Update","SQL Update","Office Update", "Anti_Virus Pattern","Java Version","Adobe Verson","Adobe Flash Version"]

  Dir.chdir("./Host_Scan_Log")
  folder = Dir.glob('*').select {|f| File.directory? f}
  folder.each do |f|
    mbsafiles = File.join(f,"PC", "*.mbsa.log")
    mfile = Dir.glob(mbsafiles)
    doc = File.open(mfile[0]) { |f1| Nokogiri::XML(f1) }

    #windows update
    w_list = get_mbsa(doc,"//Check[@Name='Windows Security Updates']")
    #SQL update
    sql_list = get_mbsa(doc,"//Check[@Name='SQL Server Security Updates']")

    #Office Update
    off_list = get_mbsa(doc,"//Check[@Name='Office Security Updates']")

    #Java FIle
    javafiles = File.join(f,"PC", "*.java.log")
    jfile = Dir.glob(javafiles)
    #puts jfile

    javadata = File.open(jfile[0])
    #java
    javafile  = filter_garbled(javadata.each_char)
    javalist  = get_java(javafile)
    #ip
    ipaddr = get_iplist(javafile)

    #anti_virus
    anti_files = File.join(f,"PC", "*.anti_virus.log")
    anfile = Dir.glob(anti_files)
    antidata = File.open(anfile[0])
    antifile  = filter_garbled(antidata.each_char)
    anti_pattern = get_antipattern(antifile)


    #adobe
    adobe_files = File.join(f,"PC", "*.adobe.log")
    adfile = Dir.glob(adobe_files)
    adobedata = File.open(adfile[0])
    adobefile  = filter_garbled(adobedata.each_char)
    adobe_version = get_adobe(adobefile)

    #flash
    #adobe
    flash_files = File.join(f,"PC", "*.flash.player.log")
    afile = Dir.glob(flash_files)
    flashdata = File.open(afile[0])
    flashfile  = filter_garbled(flashdata.each_char)
    flashversion = get_flash(flashfile)


    csv << [f,w_list.count,sql_list.count,off_list.count]
    if w_list.count == 0 then w_list << 'updated to the latest' end
    if sql_list.count == 0 then sql_list << 'updated to the latest' end
    if off_list.count == 0 then off_list << 'updated to the latest'  end
    if (javalist == '')then javalist << 'No Java' end
    if (flashversion == '')then flashversion << 'No Flash' end
    if (adobe_version == '')then adobe_version << 'No Adobe' end
    if (anti_pattern == 'Unstall')then
      anti_pattern << 'No Install'
    else
      anti_patt = Integer(anti_pattern,0).to_s
      anti_pattern = 'ver.'<< anti_patt[0]<<anti_patt[1]<<'.'<<anti_patt[2]<<anti_patt[3]<<anti_patt[4]<<'.'<<anti_patt[5]<<anti_patt[6]
    end
    csv << [ipaddr.join(','),w_list.join(','),sql_list.join(','),off_list.join(','),anti_pattern,javalist,adobe_version,flashversion]
  end
end
