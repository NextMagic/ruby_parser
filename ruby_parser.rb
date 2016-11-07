require 'nokogiri'
require 'open-uri'
require "csv"

  CSV.open("resule.csv", "wb") do |csv|
  csv << ["HOST Name", "Windows Update","SQL Update","Office Update", "Anti_Virus Pattern","Java Version","Adobe Verson","Adobe Flash Version"]

  Dir.chdir("./Host_Scan_Log")
  folder = Dir.glob('*').select {|f| File.directory? f}
  folder.each do |f|
    mbsafiles = File.join(f,"PC", "*.mbsa.log")
    mfile = Dir.glob(mbsafiles)
    doc = File.open(mfile[0]) { |f1| Nokogiri::XML(f1) }

    #windows update
    w_list = []
    doc.xpath("//Check[@Name='Windows Security Updates']").each do |f_windows|
      #puts "#{f_windows.attributes['Name']}"
      f_windows.xpath("./Detail/UpdateData[@IsInstalled='false'][@Severity>=4]").each do |f_update|
        w_list << "KB#{f_update.attributes['KBID']}"
      end
    end
    #puts "Windows update is #{w_list}"
    #SQL update
    sql_list = []
    doc.xpath("//Check[@Name='SQL Server Security Updates']").each do |f_sql|
      #puts "#{f_sql.attributes['Name']}"

      f_sql.xpath("./Detail/UpdateData[@IsInstalled='false'][@Severity>=4]").each do |f_update|
        sql_list << "KB#{f_update.attributes['KBID']}"
      end
    end
    #puts "Sql update is #{sql_list}"
    #Office Update
    off_list = []
    doc.xpath("//Check[@Name='Office Security Updates']").each do |f_office|
    #  puts "#{f_office.attributes['Name']}"
      f_office.xpath("./Detail/UpdateData[@IsInstalled='false'][@Severity>=4]").each do |f_update|
        off_list << "KB#{f_update.attributes['KBID']}"
      end
    end
    #puts "Office update is #{off_list}"

    #Java FIle
    javafiles = File.join(f,"PC", "*.java.log")
    jfile = Dir.glob(javafiles)
    puts jfile
    doc = File.open(jfile[0])

    csv << [f,w_list.count,sql_list.count,off_list.count]
    csv << ['IP',w_list,sql_list,off_list]
  end
end
