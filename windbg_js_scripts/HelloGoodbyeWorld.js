"use strict";

var log = host.diagnostics.debugLog;

function invokeScript()
{
    log("Hello world from `invokeScript`\n");
}

function initializeScript()
{
    log("Hello world from `initializeScript`\n");
}

function uninitializeScript()
{
    log("Goodbye world from `uninitializeScript`\n");
}

