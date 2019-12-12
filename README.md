# sysrepo-tsn
Sysrepo-tsn is an application to implement tsn configuration. It is based on sysrepo, a NETCONF datastore implementation.

In this project, we use tsn related models from [yang](https://github.com/YangModels/yang),
like [ieee802-dot1q-preemption.yang](https://github.com/YangModels/yang/tree/master/standard/ieee/draft/802.1/Qcw),
as our models' source to creat netopeer transAPI.
Sysrepo-tsn together with netopeer2 server in the device can implement tsn configuration based on NETCONF protocol.
