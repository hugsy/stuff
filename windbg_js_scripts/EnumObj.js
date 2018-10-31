"use strict";


const log = x => host.diagnostics.debugLog(x + "\n");


function invokeScript()
{

    var ptrsz = host.namespace.Debugger.State.PseudoRegisters.General.ptrsize;
    var hdrsz = host.evaluateExpression("sizeof(_OBJECT_HEADER)");

    //
    // We must substract because _OBJECT_HEADER and the object body itself overlap by sizeof(void*)
    // http://codemachine.com/article_objectheader.html
    //
    var hdroff = hdrsz - ptrsz;

    //
    // x nt!ObpRootDirectoryObject
    //
    var pObpRootDirectoryObject = host.getModuleSymbolAddress("nt", "ObpRootDirectoryObject");

    //
    // dx (_OBJECT_DIRECTORY*)&nt!ObpRootDirectoryObject
    //
    var RootDirectoryObject = host.createPointerObject(pObpRootDirectoryObject, "nt", "_OBJECT_DIRECTORY *");


    //
    // On each HashBucket
    //
    for(var i=0; i<RootDirectoryObject.HashBuckets.Count(); i++)
    {
        try
        {
            //
            // Find the object header and dump infos
            //
            var ObjDirEntry = RootDirectoryObject.HashBuckets[i];
            var ObjectHeaderAddress = ObjDirEntry.Object.address.subtract(hdroff);
            var ObjectHeader = host.createPointerObject(ObjectHeaderAddress, "nt", "_OBJECT_HEADER*");
            log(i.toString() + " " + ObjectHeaderAddress.toString(16) + " " + ObjectHeader.ObjectName + " (" + ObjectHeader.ObjectType + ")");
        }
        catch(err){}
    }

}


