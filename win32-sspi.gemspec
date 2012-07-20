require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'win32-eventlog'
  spec.version    = '0.0.1'
  spec.authors    = ['Daniel J. Berger'],
  spec.license    = 'Artistic 2.0'
  spec.email      = 'djberg96@gmail.com'
  spec.homepage   = 'https://github.com/djberg96/win32-sspi'
  spec.summary    = 'Yet another SSPI library for Windows'
  spec.test_files = Dir['test/*.rb']
  spec.files      = Dir['**/*'].reject{ |f| f.include?('git') }

  spec.rubyforge_project = 'win32utils'
  spec.extra_rdoc_files  = ['README']

  spec.add_dependency('ffi')
  spec.add_development_dependency('test-unit')

  spec.description = <<-EOF
    Experimental SSPI library for Ruby on Windows using FFI under the hood.
  EOF
end
