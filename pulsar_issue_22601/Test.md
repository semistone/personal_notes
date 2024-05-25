## Pulsar consume event corrupt repo steps

[Issue 22601](https://github.com/apache/pulsar/issues/22601)

### Start single node cluster

- Download and extract apache-pulsar-3.2.2-bin.tar.gz
- follow https://pulsar.apache.org/docs/3.2.x/deploy-bare-metal/#hardware-considerations
```text
bin/pulsar initialize-cluster-metadata \
    --cluster pulsar-cluster-1 \
    --metadata-store zk:localhost:2181 \
    --configuration-metadata-store zk:localhost:2181 \
    --web-service-url http://localhost:8080 \
    --web-service-url-tls https://localhost:8443 \
    --broker-service-url pulsar://localhost:6650 \
    --broker-service-url-tls pulsar+ssl://localhost:6651
```
- bin/pulsar-daemon  start zookeeper
### Enable bookkeeper TLS
#### conf/bookkeeper.conf
```text
# TLS Provider (JDK or OpenSSL).
tlsProvider=OpenSSL

# The path to the class that provides security.
tlsProviderFactoryClass=org.apache.bookkeeper.tls.TLSContextFactory

# Type of security used by server.
tlsClientAuthentication=true

# Bookie Keystore type.
tlsKeyStoreType=JKS

# Bookie Keystore location (path).
tlsKeyStore=conf/keystore.jks

# Bookie Keystore password path, if the keystore is protected by a password.
tlsKeyStorePasswordPath=conf/.pass

# Bookie Truststore type.
tlsTrustStoreType=JKS

# Bookie Truststore location (path).
tlsTrustStore=conf/truststore.jks

# Bookie Truststore password path, if the trust store is protected by a password.
tlsTrustStorePasswordPath=conf/.pass
```
#### broker.conf
```text
bookkeeperTLSProviderFactoryClass=org.apache.bookkeeper.tls.TLSContextFactory

# Enable tls authentication with bookie
bookkeeperTLSClientAuthentication=true

# Supported type: PEM, JKS, PKCS12. Default value: PEM
bookkeeperTLSKeyFileType=JKS

#Supported type: PEM, JKS, PKCS12. Default value: PEM
bookkeeperTLSTrustCertTypes=JKS

# Path to file containing keystore password, if the client keystore is password protected.
bookkeeperTLSKeyStorePasswordPath=conf/.pass

# Path to file containing truststore password, if the client truststore is password protected.
bookkeeperTLSTrustStorePasswordPath=conf/.pass

# Path for the TLS private key file
bookkeeperTLSKeyFilePath=conf/keystore.jks

# Path for the TLS certificate file
bookkeeperTLSCertificateFilePath=

# Path for the trusted TLS certificate file
bookkeeperTLSTrustCertsFilePath=conf/truststore.jks
```

### Change pulsar-testclient
Build pulsar-testclient.jar from https://github.com/semistone/pulsar/tree/debug_ssues_22601

Replace pulsar-testclient.jar in lib/org.apache.pulsar-pulsar-testclient-3.2.2.jar



### Run Test
consume 10 consumers
wait consumer started, then
produce 6000 qps , payload 2k, 2% 20k no batch mode.

- bin/pulsar-perf  consume  persistent://public/default/my-topic  -n 10 -sp Latest -ss angus_test    -st Key_Shared
- bin/pulsar-perf  produce persistent://public/default/my-topic -r 6000 -s 2000 -bp 2    -db   -b 1

#### Error log
this error will happen immediately in broker's log.
```text
2024-05-25T11:05:33,502+0000 [broker-topic-workers-OrderedExecutor-14-0] ERROR org.apache.pulsar.common.protocol.Commands - [PersistentSubscription{topic=persistent://public/default/my-topic-1, name=angus_test}] [-1] Failed to parse message metadata
java.lang.IllegalArgumentException: Invalid unknonwn tag type: 3
        at org.apache.pulsar.common.api.proto.LightProtoCodec.skipUnknownField(LightProtoCodec.java:270) ~[org.apache.pulsar-pulsar-common-3.2.2.jar:3.2.2]
        at org.apache.pulsar.common.api.proto.MessageMetadata.parseFrom(MessageMetadata.java:1370) ~[org.apache.pulsar-pulsar-common-3.2.2.jar:3.2.2]
        at org.apache.pulsar.common.protocol.Commands.parseMessageMetadata(Commands.java:460) ~[org.apache.pulsar-pulsar-common-3.2.2.jar:3.2.2]
        at org.apache.pulsar.common.protocol.Commands.parseMessageMetadata(Commands.java:447) ~[org.apache.pulsar-pulsar-common-3.2.2.jar:3.2.2]
        at org.apache.pulsar.common.protocol.Commands.peekMessageMetadata(Commands.java:1936) ~[org.apache.pulsar-pulsar-common-3.2.2.jar:3.2.2]
        at org.apache.pulsar.common.protocol.Commands.peekAndCopyMessageMetadata(Commands.java:1955) ~[org.apache.pulsar-pulsar-common-3.2.2.jar:3.2.2]
        at org.apache.pulsar.broker.service.AbstractBaseDispatcher.filterEntriesForConsumer(AbstractBaseDispatcher.java:143) ~[org.apache.pulsar-pulsar-broker-3.2.2.jar:3.2.2]
        at org.apache.pulsar.broker.service.AbstractBaseDispatcher.filterEntriesForConsumer(AbstractBaseDispatcher.java:101) ~[org.apache.pulsar-pulsar-broker-3.2.2.jar:3.2.2]
        at org.apache.pulsar.broker.service.persistent.PersistentStickyKeyDispatcherMultipleConsumers.trySendMessagesToConsumers(PersistentStickyKeyDispatcherMultipleConsumers.java:290) ~[org.apache.pulsar-pulsar-broker-3.2.2.jar:3.2.2]
        at org.apache.pulsar.broker.service.persistent.PersistentDispatcherMultipleConsumers.sendMessagesToConsumers(PersistentDispatcherMultipleConsumers.java:651) ~[org.apache.pulsar-pulsar-broker-3.2.2.jar:3.2.2]
        at org.apache.pulsar.broker.service.persistent.PersistentDispatcherMultipleConsumers.lambda$readEntriesComplete$8(PersistentDispatcherMultipleConsumers.java:616) ~[org.apache.pulsar-pulsar-broker-3.2.2.jar:3.2.2]
        at org.apache.bookkeeper.common.util.SingleThreadExecutor.safeRunTask(SingleThreadExecutor.java:137) ~[org.apache.bookkeeper-bookkeeper-common-4.16.4.jar:4.16.4]
        at org.apache.bookkeeper.common.util.SingleThreadExecutor.run(SingleThreadExecutor.java:113) ~[org.apache.bookkeeper-bookkeeper-common-4.16.4.jar:4.16.4]
        at io.netty.util.concurrent.FastThreadLocalRunnable.run(FastThreadLocalRunnable.java:30) ~[io.netty-netty-common-4.1.105.Final.jar:4.1.105.Final]
        at java.lang.Thread.run(Thread.java:842) ~[?:?]
2024-05-25T11:05:33,502+0000 [broker-topic-workers-OrderedExecutor-14-0] ERROR org.apache.pulsar.common.protocol.Commands - [PersistentSubscription{topic=persistent://public/default/my-topic-1, name=angus_test}] [-1] Failed to parse message metadata
```

### Investigate history

#### Reproduce by perf tool
After compare our producer and perf tool, we found the condition to trigger this issue
is when there are 1~2% payload is 20K bytes.
If we remove those events, then error disappear. So we add a small patch to allow perf tool
to send big payload percentage by option -bp 2

#### Confirm Data corrupt 
Print corrupt data in AbstractBaseDispatcher.java
```java
135             MessageMetadata msgMetadata;
136             if (metadataArray != null) {
137                 msgMetadata = metadataArray[metadataIndex];
138             } else if (entry instanceof EntryAndMetadata) {
139                 msgMetadata = ((EntryAndMetadata) entry).getMetadata();
140             } else {
141                 msgMetadata = Commands.peekAndCopyMessageMetadata(metadataAndPayload, subscription.toString(), -1);
142                 if (msgMetadata == null) {
143                    log.warn("null meta data ledger {} entry {} data is {}", entry.getLedgerId(), entry.getEntryId(), Base64.encode(entry.getData()));
144                 }
145             }

```
So we confirmed data was corrupted.

#### Check when data corrupt happen

We could use 
```java
Commands.hasChecksum(data)
```
to verify data, so we use it to check when data start to corrupt.
and found it start to happen in OpAddEntry.java
```java
        long ledgerId = ledger != null ? ledger.getId() : ((Position) ctx).getLedgerId();
        if (ml.hasActiveCursors()) {
            // Avoid caching entries if no cursor has been created
            debug.append("run create entry;");
            EntryImpl entry = EntryImpl.create(ledgerId, entryId, data);
            if (!Commands.hasChecksum(data)) {
               log.warn("no checksum {}", debug.toString()); <==== from here
            }
            debug = new StringBuilder();
            // EntryCache.insert: duplicates entry by allocating new entry and data. so, recycle entry after calling
            // insert
            ml.entryCache.insert(entry);
            entry.release();
            data.debug = null;
        }

```

but we still don't known why that bytebuf corrupted.
during try and error, I found when replace OpAddEntry.data
```java
    private static OpAddEntry createOpAddEntryNoRetainBuffer(ManagedLedgerImpl ml, ByteBuf data,
                                                             AddEntryCallback callback, Object ctx) {
        OpAddEntry op = RECYCLER.get();
        op.ml = ml;
        op.ledger = null;
        op.data = data.asReadOnly(); <===
```
then that error disappear but I still don't known why.


#### Trace data
because OpAddEntry.data is similar to private fields, so I collect debug log
whenever any operation touch OpAddEntry.data.
and when data.release() and duplicateBuffer.release()
and print those logs when data corrupted.

and the debug log show
- init retained from OpAddEntry.initiate()
- one bytebuf release from bookkeeper in
```text
2024-05-23T08:42:29,709+0000 [BookKeeperClientWorker-OrderedExecutor-14-0] WARN  org.apache.bookkeeper.mledger.impl.OpAddEntry - no checksum recycle;init retained;buf release java.lang.Exception
        at io.netty.buffer.AbstractReferenceCountedByteBuf.release(AbstractReferenceCountedByteBuf.java:109)
        at io.netty.buffer.AbstractPooledDerivedByteBuf$PooledNonRetainedDuplicateByteBuf.release0(AbstractPooledDerivedByteBuf.java:204)
        at io.netty.buffer.AbstractDerivedByteBuf.release(AbstractDerivedByteBuf.java:94)
        at io.netty.util.ReferenceCountUtil.release(ReferenceCountUtil.java:90)
        at io.netty.util.ReferenceCountUtil.safeRelease(ReferenceCountUtil.java:116)
        at org.apache.bookkeeper.proto.checksum.DigestManager.computeDigestAndPackageForSendingV2(DigestManager.java:144)
        at org.apache.bookkeeper.proto.checksum.DigestManager.computeDigestAndPackageForSending(DigestManager.java:106)
        at org.apache.bookkeeper.client.PendingAddOp.initiate(PendingAddOp.java:246)
        at org.apache.bookkeeper.client.LedgerHandle.doAsyncAddEntry(LedgerHandle.java:1358)
        at org.apache.bookkeeper.client.LedgerHandle.asyncAddEntry(LedgerHandle.java:1056)
        at org.apache.bookkeeper.mledger.impl.OpAddEntry.initiate(OpAddEntry.java:150)
        at org.apache.bookkeeper.mledger.impl.ManagedLedgerImpl.internalAsyncAddEntry(ManagedLedgerImpl.java:862)
        at org.apache.bookkeeper.mledger.impl.ManagedLedgerImpl.lambda$asyncAddEntry$2(ManagedLedgerImpl.java:778)
        at org.apache.bookkeeper.common.util.SingleThreadExecutor.safeRunTask(SingleThreadExecutor.java:137)
        at org.apache.bookkeeper.common.util.SingleThreadExecutor.run(SingleThreadExecutor.java:107)
        at io.netty.util.concurrent.FastThreadLocalRunnable.run(FastThreadLocalRunnable.java:30)
        at java.base/java.lang.Thread.run(Thread.java:842)
```
- another bytebuffer been released from bookkeeper in
```text
buf release java.lang.Exception
        at io.netty.buffer.AbstractReferenceCountedByteBuf.release(AbstractReferenceCountedByteBuf.java:109)
        at io.netty.buffer.AbstractPooledDerivedByteBuf$PooledNonRetainedDuplicateByteBuf.release0(AbstractPooledDerivedByteBuf.java:204)
        at io.netty.buffer.AbstractDerivedByteBuf.release(AbstractDerivedByteBuf.java:94)
        at org.apache.bookkeeper.proto.checksum.DigestManager.computeDigestAndPackageForSendingV2(DigestManager.java:163)
        at org.apache.bookkeeper.proto.checksum.DigestManager.computeDigestAndPackageForSending(DigestManager.java:106)
        at org.apache.bookkeeper.client.PendingAddOp.initiate(PendingAddOp.java:246)
        at org.apache.bookkeeper.client.LedgerHandle.doAsyncAddEntry(LedgerHandle.java:1358)
        at org.apache.bookkeeper.client.LedgerHandle.asyncAddEntry(LedgerHandle.java:1056)
        at org.apache.bookkeeper.mledger.impl.OpAddEntry.initiate(OpAddEntry.java:150)
        at org.apache.bookkeeper.mledger.impl.ManagedLedgerImpl.internalAsyncAddEntry(ManagedLedgerImpl.java:862)
        at org.apache.bookkeeper.mledger.impl.ManagedLedgerImpl.lambda$asyncAddEntry$2(ManagedLedgerImpl.java:778)
        at org.apache.bookkeeper.common.util.SingleThreadExecutor.safeRunTask(SingleThreadExecutor.java:137)
        at org.apache.bookkeeper.common.util.SingleThreadExecutor.run(SingleThreadExecutor.java:107)
        at io.netty.util.concurrent.FastThreadLocalRunnable.run(FastThreadLocalRunnable.java:30)
        at java.base/java.lang.Thread.run(Thread.java:842)

```

- run create entry in EntryImpl entry = EntryImpl.create(ledgerId, entryId, data);
- data corrupted.

After discuss with Lari Hotari, seem he found the root cause.


