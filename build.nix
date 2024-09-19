{ pkgs ? import <nixpkgs> { config.allowUnfree = true; } }:
pkgs.callPackage ./. {}
