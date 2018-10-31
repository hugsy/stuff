/**
 *
 * Basic example to show how to document a function directly via `dx`, and create a MASM-like function alias.
 *
 * Will show a greeting message upon init, or if called directly via
 *
 * 0:000> dx @$scripts.Greetings.Contents.greet("MyName")
 * or
 * 0:000> dx @$scriptContents.greet("MyName")
 *
 * or
 *
 * 0:000> !greet ""MyName"
 *
 * The documentation can be viewed with :
 *
 * 0:000> dx @$scriptContents.greet
 */

"use strict";

const log = x => host.diagnostics.debugLog(x + "\n");


class EnvironmentVariable
{
    constructor(addr, name, value)
    {
        this.Address = addr
        this.Name = name;
        this.Value = value;
    }

    toString()
    {
        return "(" + this.Address.toString(16) + ") " + this.Name + "=" + this.Value;
    }
}


/**
 * Generator to inspect the PEB looking for the Environment variables from PEB
 */
function *GetEnvironmentVariables()
{
    var EnvironmentVariables = [];
    var Peb = host.namespace.Debugger.Sessions[0].Processes.First().Environment.EnvironmentBlock;
    var EnvVarBlockAddr = Peb.ProcessParameters.Environment.address;
    var off = 0;
    while (true)
    {
        var addr = EnvVarBlockAddr.add(off);
        // var Env = host.evaluateExpression("(wchar_t*)" + EnvVarBlockAddr.add(off)) ;
        var env = host.memory.readWideString(addr);
        if (env.length == 0)
        {
            // end of envvar
            break;
        }

        if (env.indexOf("="))
        {
            let p = env.split("=");
            var Env = new EnvironmentVariable(addr, p[0], p[1]);
        }
        else
        {
            var Env = new EnvironmentVariable(addr, env, "");
        }

        yield (Env);
        off += (env.length+1)*2;
    }
}


/**
 * Be polite
 */
function greet(name)
{
    log("Greetings " + name + ", happy debugging!");
}

host.metadata.defineMetadata(this, { greet: { Help : "Say hello" } });


/**
 * Initialize the function alias.
 */
function initializeScript()
{
    return [
        new host.functionAlias(greet, "greet"),
        new host.functionAlias(GetEnvironmentVariables, "env")
    ];
}


/**
 * main()
 */
function invokeScript()
{
    var name = "Stranger";

    for (var env of GetEnvironmentVariables())
    {
        if (env.Name == "USERNAME")
        {
            name = env.Value;
            break;
        }
    }

    greet(name);
}
