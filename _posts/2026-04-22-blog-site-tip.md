---
title: Blog Management Tips - 1
categories: [tips, blog]
tags: [trick, blog]
---

### markdown lexer
目前markdown的语法高亮使用的是jekyll自带的Rouge. 可以通过下列命令查看支持什么语言：
```
bundle exec ruby -e 'require "rouge"; Rouge::Lexer.all.sort_by(&:tag).each { |l| puts ([l.tag] + l.aliases).compact.uniq.join(",") }'
```
另外，可以在 `_plugin`目录下增加语法别名文件，下面就是把asm等内容都用nasm的解析规则来渲染高亮.
```ruby
# rouge-lexer-aliases.rb

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
```