// SPDX-FileCopyrightText: 2019-Present Famedly GmbH
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:test/test.dart';
import 'package:vodozemac/vodozemac.dart' as vod;

import 'package:matrix/encryption/utils/session_key.dart';

void main() {
  group('Megolm v2 inbound fallback', () {
    setUpAll(() async {
      await vod.init(libraryPath: './rust/target/debug/');
    });

    SessionKey buildSession(vod.InboundGroupSession inbound, String sessionId) =>
        SessionKey(
          content: <String, dynamic>{},
          inboundGroupSession: inbound,
          key: '@alice:example.com',
          roomId: '!room:example.com',
          sessionId: sessionId,
          senderKey: 'sender-curve25519',
          senderClaimedKeys: <String, String>{},
        );

    test('decrypts a v2 message via a v1 session and marks needsPersist', () {
      // A peer/older build encrypts with the pre-0.10 default (Megolm v2,
      // full 32-byte MAC).
      final outbound = vod.GroupSession(useMegolmV2: true);
      final rawSessionKey = outbound.sessionKey;
      final encrypted = outbound.encrypt('hello v2');

      // Our inbound session is built with the current v1 default (8-byte MAC).
      final session = buildSession(
        vod.InboundGroupSession(rawSessionKey),
        outbound.sessionId,
      );

      expect(session.needsPersist, isFalse);

      // Direct v1 decrypt would throw "invalid MAC length: expected 8, got 32";
      // the SessionKey wrapper rebuilds as v2 and recovers the message.
      final result = session.decrypt(encrypted);
      expect(result.plaintext, 'hello v2');
      expect(session.needsPersist, isTrue);
    });

    test('normal v1 messages decrypt without upgrading', () {
      final outbound = vod.GroupSession();
      final rawSessionKey = outbound.sessionKey;
      final encrypted = outbound.encrypt('hello v1');

      final session = buildSession(
        vod.InboundGroupSession(rawSessionKey),
        outbound.sessionId,
      );

      final result = session.decrypt(encrypted);
      expect(result.plaintext, 'hello v1');
      expect(session.needsPersist, isFalse);
    });
  });
}
