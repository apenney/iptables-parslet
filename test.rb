#!/usr/bin/env ruby

require 'parslet'
require 'parslet/convenience'
require 'pp'

class IpParser < Parslet::Parser
  root(:firewall)

  rule(:firewall)      { table.repeat(1).as(:firewall) >> eol }
  rule(:table)         { (name.as(:name) >> (chain.repeat(1)).as(:chains) >> rule.repeat(1).as(:rules)).as(:table) >> commit }
  rule(:name)          { star >> line >> eol }
  rule(:chain)         { (colon >> word.as(:name) >> space >>
                          word.as(:policy) >> space >>
                         left_bracket >> integers.as(:packet_counter) >>
                         colon >> integers.as(:byte_counter) >>
                         right_bracket >> eol).as(:chain) }
  rule(:rule)          { (rule_piece.repeat(1)).as(:rule) >> eol }
  rule(:rule_piece)    { (argument >> nondash.maybe).as(:piece) }


  rule(:commit)        { str('COMMIT') >> eol }
  rule(:star)          { str('*') }
  rule(:line)          { match['^\n'].repeat(1) }
  rule(:eol)           { match["\n"] }
  rule(:colon)         { str(':') }
  rule(:word)          { match['\S'].repeat(1) }
  rule(:word?)         { word.maybe }
  rule(:nondash)       { match['^-\n'].repeat(1) }
  rule(:space)         { match('\s').repeat(1) }
  rule(:space?)        { space.maybe }
  rule(:dash)          { str('-') }
  rule(:left_bracket)  { str('[') }
  rule(:right_bracket) { str(']') }
  rule(:integers)      { match['0-9'].repeat(1) }
  rule(:negation)      { str('!') }
  rule(:negation?)     { negation.maybe }
  rule(:argument)      { dash >> word }
end


def parse(str)
  iptables = IpParser.new
  iptables.parse_with_debug(str)
end

stuff = File.read('./example').gsub(/^#.*\n/, '')
pp parse(stuff)
