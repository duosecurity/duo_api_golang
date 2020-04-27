# Overview

[![Build Status](https://travis-ci.org/duosecurity/duo_api_golang.svg?branch=master)](https://travis-ci.org/duosecurity/duo_api_golang)
[![Issues](https://img.shields.io/github/issues/duosecurity/duo_api_golang)](https://github.com/duosecurity/duo_api_golang/issues)
[![Forks](https://img.shields.io/github/forks/duosecurity/duo_api_golang)](https://github.com/duosecurity/duo_api_golang/network/members)
[![Stars](https://img.shields.io/github/stars/duosecurity/duo_api_golang)](https://github.com/duosecurity/duo_api_golang/stargazers)
[![License](https://img.shields.io/badge/License-View%20License-orange)](https://github.com/duosecurity/duo_api_golang/blob/master/LICENSE)

**duo_api_golang** - Go language bindings for the Duo APIs (both auth and admin).

## Duo Auth API

The Auth API is a low-level, RESTful API for adding strong two-factor authentication to your website or application.

This module's API client implementation is *complete*; corresponding methods are exported for all available endpoints.

For more information see the [Auth API guide](https://duo.com/docs/authapi).

## Duo Admin API

The Admin API provides programmatic access to the administrative functionality of Duo Security's two-factor authentication platform.

This module's API client implementation is *incomplete*; methods for fetching most entity types are exported, but methods that modify entities have (mostly) not yet been implemented. PRs welcome!

For more information see the [Admin API guide](https://duo.com/docs/adminapi).
