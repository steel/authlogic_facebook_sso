# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run the gemspec command
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{authlogic_facebook}
  s.version = "0.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Rusty Burchfield"]
  s.date = %q{2009-12-03}
  s.description = %q{Authlogic plugin to support Facebook without Facebooker}
  s.email = %q{GICodeWarrior@gmail.com}
  s.extra_rdoc_files = [
    "LICENSE",
     "README.rdoc"
  ]
  s.files = [
    ".document",
     ".gitignore",
     "LICENSE",
     "README.rdoc",
     "Rakefile",
     "VERSION",
     "lib/authlogic_facebook.rb",
     "lib/authlogic_facebook/acts_as_authentic.rb",
     "lib/authlogic_facebook/helper.rb",
     "lib/authlogic_facebook/session.rb",
     "spec/authlogic_facebook_spec.rb",
     "spec/spec.opts",
     "spec/spec_helper.rb"
  ]
  s.homepage = %q{http://github.com/GICodeWarrior/authlogic_facebook}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.5}
  s.summary = %q{Authlogic plugin to support Facebook without Facebooker}
  s.test_files = [
    "spec/spec_helper.rb",
     "spec/authlogic_facebook_spec.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<mini_fb>, [">= 0.1.0"])
      s.add_development_dependency(%q<rspec>, [">= 1.2.9"])
    else
      s.add_dependency(%q<mini_fb>, [">= 0.1.0"])
      s.add_dependency(%q<rspec>, [">= 1.2.9"])
    end
  else
    s.add_dependency(%q<mini_fb>, [">= 0.1.0"])
    s.add_dependency(%q<rspec>, [">= 1.2.9"])
  end
end

