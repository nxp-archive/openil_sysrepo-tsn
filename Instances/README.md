# Introduction of Instance files
Instance files in this derectory can be used to configure tsn features with Netopeer2 or Netopeer(Netopeer2 was recommended).

# Tips on operation to yang items:
- Add leafref node

Before Adding a new leafref node, be sure that there already have the leaf to be referenced in datastore or in the same Instance.

For example, there have a `<sfsg:stream-gate-ref>2</sfsg:stream-gate-ref>` node in `stream-filter-swp0.xml`.
Before applying this instance, we should configure stream-gate's instance with `<sfsg:stream-gate-instance-id>2</sfsg:stream-gate-instance-id>` first.

In other words, the operation to configure a leafref node requires reasonable order.

- Delete items from current datastore

To delete an item(container, list, leaf etc.), `netconf` module should be used.
Then put `nc:operation="delete"` in the end of start tag of the item to be deleted.
You can find examples in `xxx-disable.xml`.

# Not used items
There have some items just for YANG format validation, like `<bridge-type>` in `bridge` contaniner.
Content of these items is not impotent, What you should focus on are the constraints of these items.
Following are the list of these items:

```
/bridges/bridge/bridge-type
/bridges/bridge/address
/bridges/bridge/component/type
/interfaces/interface/enabled
/interfaces/interface/type
```
