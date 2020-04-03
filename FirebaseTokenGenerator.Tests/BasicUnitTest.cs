using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Newtonsoft.Json;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FirebaseTokenGenerator.Tests
{
    public class Tests
    {
        private string FIREBASE_SUPER_SECRET_KEY = "moozooherpderp";

        [Test]
        public void Dummy()
        {
            Assert.Pass();
        }

        [Test]
        public void CheckIfBasicLength()
        {
            Assert.Throws<Exception>(() =>
            {
                var payload = new Dictionary<string, object>();

                var tokenGenerator = new TokenGenerator("x");
                var token = tokenGenerator.CreateToken(payload);
            });
        }

        [Test]
        public void CheckBasicStructureHasCorrectNumberOfFragments()
        {
            var payload = new Dictionary<string, object>
            {
                { "uid", "1" },
                { "abc", "0123456789~!@#$%^&*()_+-=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,./;'[]\\<>?\"{}|" }
            };

            var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
            var token = tokenGenerator.CreateToken(payload);

            String[] tokenFragments = token.Split('.');

            Assert.IsTrue(tokenFragments.Length == 3, "Token has the proper number of fragments: jwt metadata, payload, and signature");
        }

        [Test]
        public void CheckResultProperlyDoesNotHavePadding()
        {
            var payload = new Dictionary<string, object>
            {
                { "uid", "1" },
                { "abc", "0123456789~!@#$%^&*()_+-=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,./;'[]\\<>?\"{}|" }
            };

            var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
            var token = tokenGenerator.CreateToken(payload);

            Assert.IsTrue(token.IndexOf('=') < 0);
        }

        [Test]
        public void CheckIfResultIsUrlSafePlusSign()
        {
            var payload = new Dictionary<string, object>
            {
                { "uid", "1" },
                { "abc", "0123456789~!@#$%^&*()_+-=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,./;'[]\\<>?\"{}|" }
            };

            var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
            var token = tokenGenerator.CreateToken(payload);

            Assert.IsTrue(token.IndexOf('+') < 0);
        }

        [Test]
        public void CheckIfResultIsUrlSafePlusSlash()
        {
            var payload = new Dictionary<string, object>
            {
                { "uid", "1" },
                { "abc", "0123456789~!@#$%^&*()_+-=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,./;'[]\\<>?\"{}|" }
            };

            var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
            var token = tokenGenerator.CreateToken(payload);

            Assert.IsTrue(token.IndexOf('/') < 0);
        }

        [Test]
        public void CheckIfResultHasWhiteSpace()
        {
            var payload = new Dictionary<string, object>
            {
                { "uid", "1" },
                { "a", "apple" },
                { "b", "banana" },
                { "c", "carrot" },
                { "number", Double.MaxValue },
                { "abc", "0123456789~!@#$%^&*()_+-=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,./;'[]\\<>?\"{}|" },
                { "herp1", "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.?" }
            };

            var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
            var token = tokenGenerator.CreateToken(payload);

            var pattern = new Regex(@"\s");
            var hasWhiteSpace = pattern.IsMatch(token);

            Assert.IsFalse(hasWhiteSpace, "Token has white space");
        }

        [Test]
        public void BasicInspectTest()
        {
            var customData = "0123456789~!@#$%^&*()_+-=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,./;'[]\\<>?\"{}|";
            var payload = new Dictionary<string, object>
            {
                { "uid", "1" },
                { "abc", customData }
            };

            var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
            var tokenOptions = new TokenOptions(DateTime.Now, DateTime.Now, true, true);

            var token = tokenGenerator.CreateToken(payload, tokenOptions);

            var jwtDecoder = new JWT.JwtDecoder(new JsonNetSerializer(), new JwtValidator(new JsonNetSerializer(), new UtcDateTimeProvider()), new JwtBase64UrlEncoder(), new HMACSHA256Algorithm());
            var decoded = jwtDecoder.DecodeToObject(token);

            Assert.Multiple(() =>
            {
                Assert.IsTrue(decoded.ContainsKey("v"));
                Assert.IsTrue(int.Parse(decoded["v"].ToString()) == 0);
                Assert.IsTrue(decoded["v"] is long);

                Assert.IsTrue(decoded.ContainsKey("d"));
                var c = decoded["d"];
                var json = JsonConvert.SerializeObject(c);
                var dictionary = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
                Assert.IsTrue(dictionary.ContainsKey("abc"));

                Assert.IsTrue(decoded.ContainsKey("exp"));
                Assert.IsTrue(decoded["exp"] is long);

                Assert.IsTrue(decoded.ContainsKey("iat"));
                Assert.IsTrue(decoded["iat"] is long);

                Assert.IsTrue(decoded.ContainsKey("nbf"));
                Assert.IsTrue(decoded["nbf"] is long);

                Assert.IsTrue(decoded.ContainsKey("admin"));
                Assert.IsTrue(decoded["admin"] is bool);

                Assert.IsTrue(decoded.ContainsKey("debug"));
                Assert.IsTrue(decoded["debug"] is bool);
            }
            );
        }

        [Test]
        public void RequireUidInPayload()
        {
            Assert.Throws<Exception>(() =>
            {
                var payload = new Dictionary<string, object>
                {
                    { "abc", "0123456789~!@#$%^&*()_+-=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,./;'[]\\<>?\"{}|" }
                };

                var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
                var token = tokenGenerator.CreateToken(payload);
            });
        }

        [Test]
        public void RequireUidStringInPayload()
        {
            Assert.Throws<Exception>(() =>
            {
                var payload = new Dictionary<string, object>
                {
                    { "uid", 1 }
                };

                var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
                var token = tokenGenerator.CreateToken(payload);
            });
        }

        [Test]
        public void AllowMaxLengthUid()
        {
            var payload = new Dictionary<string, object>
            {
                //                10        20        30        40        50        60        70        80        90       100       110       120       130       140       150       160       170       180       190       200       210       220       230       240       250   256
                { "uid", "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456" }
            };

            var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
            var token = tokenGenerator.CreateToken(payload);
        }

        [Test]
        public void DisallowUidTooLong()
        {
            Assert.Throws<Exception>(() =>
            {
                var payload = new Dictionary<string, object>
                {
                    //                10        20        30        40        50        60        70        80        90       100       110       120       130       140       150       160       170       180       190       200       210       220       230       240       250    257
                    { "uid", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567" }
                };

                var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
                var token = tokenGenerator.CreateToken(payload);
            });
        }

        [Test]
        public void AllowEmptyStringUid()
        {
            var payload = new Dictionary<string, object>
            {
                { "uid", "" }
            };

            var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
            var token = tokenGenerator.CreateToken(payload);
        }

        [Test]
        public void DisallowTokensTooLong()
        {
            Assert.Throws<Exception>(() =>
            {
                var payload = new Dictionary<string, object>
                {
                    { "uid", "blah" },
                    { "longVar", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345612345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234561234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456" }
                };

                var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
                var token = tokenGenerator.CreateToken(payload);
            });
        }

        [Test]
        public void AllowNoUidWithAdmin()
        {
            var tokenOptions = new TokenOptions(null, null, true, false);

            var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
            var token = tokenGenerator.CreateToken(null, tokenOptions);
            var payload1 = new Dictionary<string, object>();
            var token1 = tokenGenerator.CreateToken(payload1, tokenOptions);
            var payload2 = new Dictionary<string, object>
            {
                { "foo", "bar" }
            };
            var token2 = tokenGenerator.CreateToken(payload2, tokenOptions);
        }

        [Test]
        public void DisallowInvalidUidWithAdmin1()
        {
            Assert.Throws<Exception>(() =>
            {
                var payload = new Dictionary<string, object>
                {
                    { "uid", 1 }
                };

                var tokenOptions = new TokenOptions(null, null, true, false);

                var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
                var token = tokenGenerator.CreateToken(payload, tokenOptions);
            });
        }

        [Test]
        public void DisallowInvalidUidWithAdmin2()
        {
            Assert.Throws<Exception>(() =>
            {
                var payload = new Dictionary<string, object>
                {
                    { "uid", null }
                };

                var tokenOptions = new TokenOptions(null, null, true, false);

                var tokenGenerator = new TokenGenerator(FIREBASE_SUPER_SECRET_KEY);
                var token = tokenGenerator.CreateToken(payload, tokenOptions);
            });
        }
    }
}