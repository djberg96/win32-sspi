require 'rake'
require 'rake/clean'
require 'rake/testtask'

CLEAN.include('**/*.gem')

namespace :gem do
  desc "Create the win32-sspi gem"
  task :create => [:clean] do
    spec = eval(IO.read('win32-sspi.gemspec'))
    Gem::Builder.new(spec).build
  end

  desc "Install the win32-sspi gem"
  task :install => [:create] do
    ruby 'win32-sspi.gemspec'
    file = Dir["*.gem"].first
    sh "gem install #{file}"
  end
end

namespace :test do
  Rake::TestTask.new(:client) do |t|
    t.test_files = FileList['test/test_win32_sspi_client.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new(:server) do |t|
    t.test_files = FileList['test/test_win32_sspi_server.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new(:all) do |t|
    t.test_files = FileList['test/test_win32*']
    t.warning = true
    t.verbose = true
  end
end

task :default => 'test:all'
