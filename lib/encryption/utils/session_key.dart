// SPDX-FileCopyrightText: 2019-Present Famedly GmbH
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:convert';

import 'package:vodozemac/vodozemac.dart' as vod;

import '../../matrix.dart';
import 'pickle_key.dart';
import 'stored_inbound_group_session.dart';

class SessionKey {
  /// The raw json content of the key
  Map<String, dynamic> content = <String, dynamic>{};

  /// Map of stringified-index to event id, so that we can detect replay attacks
  Map<String, String> indexes;

  /// Map of userId to map of deviceId to index, that we know that device receivied, e.g. sending it ourself.
  /// Used for automatically answering key requests
  Map<String, Map<String, int>> allowedAtIndex;

  /// Underlying olm [InboundGroupSession] object
  vod.InboundGroupSession? inboundGroupSession;

  /// Key for libolm pickle / unpickle
  final String key;

  /// Forwarding keychain
  List<String> get forwardingCurve25519KeyChain =>
      (content['forwarding_curve25519_key_chain'] != null
          ? List<String>.from(content['forwarding_curve25519_key_chain'])
          : null) ??
      <String>[];

  /// Claimed keys of the original sender
  late Map<String, String> senderClaimedKeys;

  /// Sender curve25519 key
  String senderKey;

  /// Is this session valid?
  bool get isValid => inboundGroupSession != null;

  /// Whether the underlying session was rebuilt with the Megolm v2 config
  /// during decryption and its upgraded pickle has not yet been persisted.
  bool needsPersist = false;

  bool _triedMegolmV2 = false;

  /// roomId for this session
  String roomId;

  /// Id of this session
  String sessionId;

  SessionKey({
    required this.content,
    required this.inboundGroupSession,
    required this.key,
    Map<String, String>? indexes,
    Map<String, Map<String, int>>? allowedAtIndex,
    required this.roomId,
    required this.sessionId,
    required this.senderKey,
    required this.senderClaimedKeys,
  }) : indexes = indexes ?? <String, String>{},
       allowedAtIndex = allowedAtIndex ?? <String, Map<String, int>>{};

  SessionKey.fromDb(StoredInboundGroupSession dbEntry, this.key)
    : content = Event.getMapFromPayload(dbEntry.content),
      indexes = Event.getMapFromPayload(
        dbEntry.indexes,
      ).catchMap((k, v) => MapEntry<String, String>(k, v)),
      allowedAtIndex = Event.getMapFromPayload(
        dbEntry.allowedAtIndex,
      ).catchMap((k, v) => MapEntry(k, Map<String, int>.from(v))),
      roomId = dbEntry.roomId,
      sessionId = dbEntry.sessionId,
      senderKey = dbEntry.senderKey {
    final parsedSenderClaimedKeys = Event.getMapFromPayload(
      dbEntry.senderClaimedKeys,
    ).catchMap((k, v) => MapEntry<String, String>(k, v));
    // we need to try...catch as the map used to be <String, int> and that will throw an error.
    senderClaimedKeys = (parsedSenderClaimedKeys.isNotEmpty)
        ? parsedSenderClaimedKeys
        : (content
                  .tryGetMap<String, dynamic>('sender_claimed_keys')
                  ?.catchMap((k, v) => MapEntry<String, String>(k, v)) ??
              (content['sender_claimed_ed25519_key'] is String
                  ? <String, String>{
                      'ed25519': content['sender_claimed_ed25519_key'],
                    }
                  : <String, String>{}));

    try {
      inboundGroupSession = vod.InboundGroupSession.fromPickleEncrypted(
        pickle: dbEntry.pickle,
        pickleKey: key.toPickleKey(),
      );
    } catch (e, s) {
      try {
        Logs().d('Unable to unpickle inboundGroupSession. Try LibOlm format.');
        inboundGroupSession = vod.InboundGroupSession.fromOlmPickleEncrypted(
          pickle: dbEntry.pickle,
          pickleKey: utf8.encode(key),
        );
      } catch (_) {
        Logs().e('[Vodozemac] Unable to unpickle inboundGroupSession', e, s);
        rethrow;
      }
    }
  }

  /// Decrypt a Megolm [ciphertext] with this session.
  ///
  /// vodozemac 0.10 made the version 1 Megolm config (8-byte truncated MAC)
  /// the default. Messages authored by peers or older builds that ran the
  /// pre-0.10 default carry a version 2 full MAC and fail here with
  /// "invalid MAC length: expected 8, got 32". On such a failure the session
  /// is rebuilt once with the version 2 config and the decryption retried; on
  /// success the upgraded session is kept and [needsPersist] is set so the
  /// caller can re-store its pickle.
  ({String plaintext, int messageIndex}) decrypt(String ciphertext) {
    final session = inboundGroupSession;
    if (session == null) {
      throw StateError('Cannot decrypt with an invalid session');
    }
    try {
      return session.decrypt(ciphertext);
    } catch (e) {
      // Only the v1-reading-v2 MAC-length mismatch is recoverable by switching
      // config. Other failures (missing key, unknown message index) must keep
      // their original error and must not consume the one-shot upgrade attempt.
      if (_triedMegolmV2 || !_isMegolmMacMismatch(e)) rethrow;
      _triedMegolmV2 = true;
      final upgraded = _rebuildAsMegolmV2(session);
      if (upgraded == null) rethrow;
      final ({String plaintext, int messageIndex}) result;
      try {
        result = upgraded.decrypt(ciphertext);
      } catch (_) {
        // The v2 retry failed for an unrelated reason; surface the original
        // error rather than a confusing "expected 32, got 8".
        throw e;
      }
      inboundGroupSession = upgraded;
      needsPersist = true;
      Logs().i('[Vodozemac] Upgraded session $sessionId to Megolm v2');
      return result;
    }
  }

  // vodozemac reports the v1-session-reads-v2-message mismatch as
  // "invalid MAC length: expected 8, got 32". "expected 8" only occurs when a
  // version 1 session parses a longer (version 2) MAC, so it uniquely
  // identifies the recoverable case. The wording is stable for the pinned
  // vodozemac; revisit this string if that dependency is bumped.
  bool _isMegolmMacMismatch(Object e) => e.toString().contains('expected 8');

  vod.InboundGroupSession? _rebuildAsMegolmV2(vod.InboundGroupSession session) {
    try {
      final exported = session.exportAtFirstKnownIndex();
      return vod.InboundGroupSession.import(exported, useMegolmV2: true);
    } catch (e, s) {
      Logs().w('[Vodozemac] Could not rebuild session as Megolm v2', e, s);
      return null;
    }
  }
}
