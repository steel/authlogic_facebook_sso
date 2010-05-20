# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run the gemspec command
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{authlogic_facebook_sso}
  s.version = "0.9"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Brian Schroeder, Rusty Burchfield"]
  s.date = %q{2010-05-07}
  s.description = %q{Authlogic plugin for Facebook single sign-on support}
  s.email = %q{bts@gmail.com}
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
     "authlogic_facebook_sso.gemspec",
     "init.rb",
     "lib/authlogic_facebook_sso.rb",
     "lib/authlogic_facebook_sso/acts_as_authentic.rb",
     "lib/authlogic_facebook_sso/helper.rb",
     "lib/authlogic_facebook_sso/session.rb",
     "rails/init.rb",
     "spec/authlogic_facebook_sso_spec.rb",
     "spec/spec.opts",
     "spec/spec_helper.rb"
  ]
  s.homepage = %q{http://github.com/bts/authlogic_facebook_sso}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.5}
  s.summary = %q{Authlogic plugin for Facebook single sign-on support}
  s.test_files = [
    "spec/authlogic_facebook_sso_spec.rb",
     "spec/spec_helper.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<authlogic>, [">= 2.1.3"])
      s.add_development_dependency(%q<rspec>, [">= 1.2.9"])
    else
      s.add_dependency(%q<authlogic>, [">= 2.1.3"])
      s.add_dependency(%q<rspec>, [">= 1.2.9"])
    end
  else
    s.add_dependency(%q<authlogic>, [">= 2.1.3"])
    s.add_dependency(%q<rspec>, [">= 1.2.9"])
  end
end
