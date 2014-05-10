#!/usr/bin/env ruby

require 'parslet'
require 'parslet/convenience'
require 'pp'

class Iptables < Parslet::Parser
  # Bits
  rule(:word)          { match['-\w\.\/\,'].repeat(1) }
  rule(:word?)         { word.maybe }
  rule(:integer)       { match['0-9'].repeat(1) }
  rule(:space)         { match('\s').repeat(1) }
  rule(:space?)        { space.maybe }
  rule(:star)          { str('*') }
  rule(:dash)          { str('-') }
  rule(:dash?)         { dash.maybe }
  rule(:colon)         { str(':') }
  rule(:left_bracket)  { str('[') }
  rule(:right_bracket) { str(']') }
  rule(:quote)         { str('"') }
  rule(:quote?)        { quote.maybe }
  rule(:newline)       { str("\n") }
  rule(:eol)           { any.absent? | newline }

  rule(:negation)      { space? >> str('!') >> space }
  rule(:negation?)     { negation.maybe }
  rule(:argument)      { dash.repeat(1) >> word.repeat(1) }
  rule(:rule_word)     { quote? >> any.repeat(1) >> quote? }
  rule(:rule_word?)    { rule_word.maybe }

  # Things
  rule(:tablename) { star >> word.repeat(1).as(:name) >> eol }
  rule(:chain)     { (colon >>
                     word.as(:name) >> space >>
                     (word.as(:policy) | dash) >> space >>
                     left_bracket >>
                     word.as(:packet_counter) >>
                     colon >>
                     word.as(:byte_counter) >>
                     right_bracket >> eol).as(:chain) }
  rule(:comment)       { str('#').repeat(1) >> any.repeat(0) >> eol }
  rule(:commit)        { str('COMMIT') >> eol }

  # -A INPUT -p ! tcp
  # -A INPUT -s 1.1.1.1 -p tcp -j ECN --ecn-tcp-remove
  rule(:rule_piece) { argument >> negation? >> rule_word? >> negation? }
  rule(:rule)       { rule_piece.repeat(1).as(:rule) }

  root(:expression)
  rule(:lines) { line.repeat }
  rule(:line) { space.repeat >> expression >> eol }
  rule(:expression) { commit | tablename | chain | comment | rule | eol }
end

def parse(str)
  iptables = Iptables.new
  iptables.parse_with_debug(str)
end

#stuff = File.read('./example')
#pp parse(stuff)
File.read('./example').each_line do |line|
  puts line.inspect
  pp parse(line)
end
