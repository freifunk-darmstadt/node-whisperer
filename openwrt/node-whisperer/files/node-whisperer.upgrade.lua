#!/usr/bin/lua5.1

local site = require 'gluon.site'
local uci = require('simple-uci').cursor()

local sources = {}
local disabled = false

if not site.node_whisperer.enabled(false) then
    disabled = true
end

for _, information in ipairs(site.node_whisperer.information({})) do
    table.insert(sources, information)
end

uci:set('node-whisperer', 'settings', 'disabled', disabled)
uci:set('node-whisperer', 'settings', 'information', sources)
uci:commit('node-whisperer')