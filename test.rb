#!/usr/bin/env ruby

require 'parslet'
require 'parslet/convenience'
require 'pp'

class Iptables < Parslet::Parser
  # Bits
  rule(:word)          { match['\w\.\/,"-'].repeat(1) }
  rule(:words)         { (word >> space?).repeat(1) }
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
  rule(:eol)           { any.absent? | newline }
  rule(:newline)       { str("\n") }

  rule(:negation)      { str('!') }
  rule(:negation?)     { negation.maybe }
  rule(:argument)      { dash.repeat(1) >> word.repeat(1) >> space_or_end }
  rule(:rule_word)     { words }
  rule(:rule_word?)    { rule_word.maybe }
  rule(:space_or_end)  { space | any.absent? }
  rule(:space_or_end?) { space_or_end.maybe }

  # Things
  rule(:tablename) { star >> word.repeat(1).as(:name) }
  rule(:chain)     { (colon >>
                     word.as(:name) >> space >>
                     (word.as(:policy) | dash) >> space >>
                     left_bracket >>
                     word.as(:packet_counter) >>
                     colon >>
                     word.as(:byte_counter) >>
                     right_bracket ).as(:chain) }
  rule(:comment)   { str('#').repeat(1) >> any.repeat(0) }
  rule(:commit)    { str('COMMIT') }

  rule(:rule)       { (rule_piece.repeat(1)).as(:rule) }
  #rule(:rule_piece) { (argument >> space_or_end? >> negation? >> space_or_end? >> rule_word? >> space_or_end).as(:piece) }
  rule(:rule_piece) { (argument >> any.repeat(1)).as(:piece) >> space_or_end }

  # This didn't work either.
  rule(:rrule_piece)    { (arg_word | arg_neg_word | arg_word_neg | arg_space | arg).as(:piece) }
  rule(:arg_word)       { argument >> space >> rule_word >> space_or_end }
  rule(:arg_neg_word)   { argument >> space >> negation >> space >> rule_word >> space_or_end }
  rule(:arg_word_neg)   { argument >> space >> rule_word >> space >> negation >> space_or_end }
  rule(:arg_space)      { argument >> space }
  rule(:arg)            { argument >> any.absent? }

  rule(:expression) { commit | tablename | chain | comment | rule | eol }
  root(:expression)
end

class Parser < Parslet::Parser
  rule(:line)      { match['^\n'] }
  rule(:star)      { str('*') }
  rule(:eol)       { match["\n"] }
  rule(:hashchar)  { str('#') }
  rule(:commit)    { str('COMMIT') }

  rule(:comment)   { (hashchar.repeat(1) >> line.repeat(0) >> eol).as(:comment) }
  rule(:table)     { ( line >> star >> match['^COMMIT'].repeat(1)).as(:tablename) }

  rule(:rule)      { table | eol | any.absent? }
  root(:rule)
end

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
  rule(:rule)          { str("-") >> line >> eol }


  rule(:commit)        { str('COMMIT') >> eol }
  rule(:star)          { str('*') }
  rule(:line)          { match['^\n'].repeat(1) }
  rule(:eol)           { match["\n"] }
  rule(:colon)         { str(':') }
  rule(:word)          { match['\S'].repeat(1) }
  rule(:space)         { match('\s').repeat(1) }
  rule(:space?)        { space.maybe }
  rule(:dash)          { str('-') }
  rule(:left_bracket)  { str('[') }
  rule(:right_bracket) { str(']') }
  rule(:integers)      { match['0-9'].repeat(1) }
end


def parse(str)
  iptables = IpParser.new
  iptables.parse_with_debug(str)
end

stuff = File.read('./example').gsub(/^#.*\n/, '')
#stuff = stuff.reject! {|l| l[0..0] == '#'}
pp parse(stuff)
#File.read('./example').each_line do |line|
#  next if line[0..0] == '#'
#  next if line[0..4] == 'COMMIT'
#  puts line.strip
#  pp parse(line.strip)
#end
