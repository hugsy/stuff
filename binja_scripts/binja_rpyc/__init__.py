"""

"""


from binaryninja import (
    PluginCommand,
) 


from .server import (
    rpyc_start,
    rpyc_stop,
    is_service_started,
)


PluginCommand.register(
    "RPyC\\Start service",
    "Start the RPyC server",
    rpyc_start,
    is_valid = lambda view: not is_service_started()
)


PluginCommand.register(
    "RPyC\\Stop service",
    "Start the RPyC server",
    rpyc_stop,
    is_valid = lambda view: is_service_started()
)