# frozen_string_literal: true

require 'rouge'

module Rouge
  module Lexers
    unless ::Rouge::Lexer.find('asm')
      class AsmAlias < Nasm
        title 'Assembly'
        desc 'Alias for NASM-style assembly'
        tag 'asm'
        aliases 'assembly', 'x86asm', 'x86_64asm'
      end
    end

    unless ::Rouge::Lexer.find('nu')
      class NushellAlias < Shell
        title 'Nushell'
        desc 'Alias that reuses shell highlighting for Nushell code fences'
        tag 'nu'
        aliases 'nushell'
      end
    end
  end
end
