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
  rule(:newline)       { str("\n") }
  rule(:eol)           { any.absent? | newline }

  rule(:negation)      { str('!') }
  rule(:negation?)     { negation.maybe }
  rule(:argument)      { dash.repeat(1) >> word.repeat(1) }
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

  rule(:rule)       { rule_piece.repeat(1).as(:rule) }
  rule(:rule_piece) { (argument >> space_or_end? >> negation? >> space_or_end? >> rule_word? >> space_or_end).as(:piece) }

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

def parse(str)
  iptables = Iptables.new
  iptables.parse_with_debug(str)
end

#stuff = File.read('./example')
#pp parse(stuff)
File.read('./example').each_line do |line|
  puts line.strip
  pp parse(line.strip)
end
