{ pkgs ? import <nixpkgs> {} }:
pkgs.callPackage ./aws-receive-mails.nix {}
