# -*- encoding: utf-8 -*-
require File.expand_path('../lib/dukpt/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["David Seal", "Cody Fauser"]
  gem.email         = ["david.seal@shopify.com", "cody@shopify.com"]
  gem.description   = %q{Implements a Derived Unique Key Per Transaction (DUKPT) decrypter}
  gem.summary       = %q{Implements a Derived Unique Key Per Transaction (DUKPT) decrypter}
  gem.homepage      = ""

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "dukpt"
  gem.require_paths = ["lib"]
  gem.version       = DUKPT::VERSION
end
