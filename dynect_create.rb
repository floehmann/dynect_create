#!/usr/bin/env ruby

require 'dynect_rest'
require 'trollop'

p = Trollop::Parser.new do
  opt :host, "Host name to add (Note: don't add domain)", :type => :string, :required => "true"
  opt :ip, "IP address of host's A record", :type => :string, :required => "true"
  opt :ip6, "IPv6 address of host's AAAA record", :type => :string, :default => ''
  opt :cname, "CNAME fqdn", :type => :string, :default => ''
  opt :rrttl, "TTL for all records in this update", :type => :integer, :default => 300
end

opts = Trollop::with_standard_exception_handling p do
  raise Trollop::HelpNeeded if ARGV.empty?
  p.parse ARGV
end

## Set variables 
DYNECT_CUST = ENV['DYNECT_CUST'] || 'customer'
DYNECT_USER = ENV['DYNECT_USER'] || 'user'
DYNECT_PASS = ENV['DYNECT_PASS'] || 'secretword'
DYNECT_ZONE = ENV['DYNECT_ZONE'] || 'example.com'

# These are required
ip = opts[:ip]
host = opts[:host].downcase

# Fix these checks and add them for valid ipv4/ipv6 addresses

# Add check for valid number
rrttl = opts[:rrttl].to_s

# Make sure host is fully qualified
if ( host =~ /#{DYNECT_ZONE}/i )
    fullhost = host
else
    fullhost = "#{host}.#{DYNECT_ZONE}"
end

# Check CNAME is fully qualified
if not opts[:cname].empty? and not opts[:cname].nil?
  cname = opts.cname.downcase
  if not cname =~ /.*\..*/i
      abort("Error: CNAME must be fully qualified.")
  end 
else
  cname = ''
end

# Check if ip6 was set
if not opts[:ip6].empty? and not opts[:ip6].nil?
  ip6 = opts.ip6
else 
  ip6 = ''
end

## Set up session
dyn = DynectRest.new(DYNECT_CUST, DYNECT_USER, DYNECT_PASS, DYNECT_ZONE, true)

## Create or Update an A Record for the given host
if not ip.empty? and not fullhost.empty?
  begin 
    a_rec = dyn.a.get(fullhost)
    a_addr = a_rec.rdata['address']
    #puts "#{fullhost} = #{a_addr}"
  rescue DynectRest::Exceptions::RequestFailed
    a_addr = ''
    #puts "#{fullhost} A record not found"
  end
end

if not a_addr.empty? and not a_addr.nil?
  puts "Updating A record #{fullhost} -> #{ip} to #{a_addr}"
  dyn.a.fqdn(fullhost).ttl(rrttl).address(ip).save(true)
else
  puts "Adding A record #{fullhost} -> #{ip}"
  dyn.a.fqdn(fullhost).ttl(rrttl).address(ip).save(false)
end

## Create or Update an AAAA Record for the given host
if not ip6.empty? and not ip6.nil?
  begin 
    aaaa_rec = dyn.aaaa.get(fullhost)
    aaaa_addr = aaaa_rec.rdata['address']
    #puts "#{fullhost} = #{aaaa_addr}"
  rescue DynectRest::Exceptions::RequestFailed
    aaaa_addr = ''
    #puts "#{fullhost} AAAA record not found"
  end
end

if not aaaa_addr.empty? and not aaaa_addr.nil?
  puts "Updating AAAA record #{fullhost} -> #{ip6} to #{aaaa_addr}"
  dyn.aaaa.fqdn(fullhost).ttl(rrttl).address(ip6).save(true)
else
  puts "Adding AAAA record #{fullhost} -> #{ip6}"
  dyn.aaaa.fqdn(fullhost).ttl(rrttl).address(ip6).save(false)
end

## Create a new CNAME record
if not cname.empty? and not cname.nil?
  begin 
    cname_rec = dyn.cname.get(cname)
    cname_fqdn = cname_rec.fqdn
    cname_target = cname_rec.rdata['cname']
    puts "WARN: CNAME exists #{cname_fqdn} -> #{cname_target} ...  Not adding."
  rescue DynectRest::Exceptions::RequestFailed
    cname_target = ''
  end
end

if cname_target.empty? or cname_target.nil?
    puts "Adding CNAME #{cname} -> #{fullhost}"
    dyn.cname.fqdn(cname).ttl(rrttl).cname(fullhost).save
end

## Publish zone
puts "Publishing #{DYNECT_ZONE}"
dyn.publish

## End session
puts "Logging off"
dyn.logout

