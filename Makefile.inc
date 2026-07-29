ALLFLAGS=-std=c++11 -Wall
CXXFLAGS=$(ALLFLAGS) -MMD -MP

ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

HAS_SVN := $(shell svn info $(ROOT_DIR) > /dev/null 2>&1; echo $$?)
REDIST_VERSION := $(shell cat $(ROOT_DIR)/.version 2>/dev/null)
GIT_HASH := $(shell git -C $(ROOT_DIR) rev-parse --short HEAD 2>/dev/null || echo "nogit")

ifeq ($(HAS_SVN), 0)
VERSION := "\"r$(shell svn info $(ROOT_DIR)|grep Revision|awk '{ print $$2 }')-franken-$(GIT_HASH)\""
else ifneq ($(REDIST_VERSION),)
VERSION := "\"r$(REDIST_VERSION)-franken-$(GIT_HASH)\""
else
VERSION := "\"unknown-franken-$(GIT_HASH)\""
endif

DATE := "\"$(shell date)\""
BOXTAG := "\"cbbncd\""
