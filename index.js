'use strict';
var token = '%[a-f0-9]{2}';
var multiMatcher = new RegExp('(' + token + ')+', 'gi');
var hexPair = /^[a-f0-9]{2}$/i;

// Backport of the decode-uri-component 0.5.0 single-pass decoder (CVE-2026-45822); 0.5.0 itself is ESM-only.
function parsePercentByte(input, position) {
	if (input.charCodeAt(position) !== 37 || position + 3 > input.length) {
		return;
	}

	var digits = input.slice(position + 1, position + 3);

	if (!hexPair.test(digits)) {
		return;
	}

	return {byte: parseInt(digits, 16), next: position + 3};
}

function utf8SequenceLength(byte) {
	if (byte <= 0x7F) {
		return 1;
	}

	if (byte >= 0xC2 && byte <= 0xDF) {
		return 2;
	}

	if (byte >= 0xE0 && byte <= 0xEF) {
		return 3;
	}

	if (byte >= 0xF0 && byte <= 0xF4) {
		return 4;
	}

	return 0;
}

function isContinuationByte(byte) {
	return byte >= 0x80 && byte <= 0xBF;
}

function decode(input) {
	try {
		return decodeURIComponent(input);
	} catch (err) {
		var output = '';
		var position = 0;

		while (position < input.length) {
			if (input.charCodeAt(position) !== 37) {
				output += input.charAt(position);
				position++;
				continue;
			}

			var firstByte = parsePercentByte(input, position);

			if (!firstByte) {
				output += input.charAt(position);
				position++;
				continue;
			}

			var sequenceLength = utf8SequenceLength(firstByte.byte);

			if (sequenceLength === 0) {
				output += input.slice(position, position + 3);
				position += 3;
				continue;
			}

			var end = firstByte.next;
			var validSequence = true;

			for (var index = 1; index < sequenceLength; index++) {
				var nextByte = parsePercentByte(input, end);

				if (!nextByte || !isContinuationByte(nextByte.byte)) {
					validSequence = false;
					break;
				}

				end = nextByte.next;
			}

			if (validSequence) {
				try {
					output += decodeURIComponent(input.slice(position, end));
					position = end;
					continue;
				} catch (err) {
					// Structurally valid but not decodable (overlong/surrogate) — fall through.
				}
			}

			output += input.slice(position, position + 3);
			position += 3;
		}

		return output;
	}
}

function customDecodeURIComponent(input) {
	// Keep track of all the replacements and prefill the map with the `BOM`
	var replaceMap = {
		'%FE%FF': '\uFFFD\uFFFD',
		'%FF%FE': '\uFFFD\uFFFD'
	};

	var match = multiMatcher.exec(input);
	while (match) {
		try {
			// Decode as big chunks as possible
			replaceMap[match[0]] = decodeURIComponent(match[0]);
		} catch (err) {
			var result = decode(match[0]);

			if (result !== match[0]) {
				replaceMap[match[0]] = result;
			}
		}

		match = multiMatcher.exec(input);
	}

	// Add `%C2` at the end of the map to make sure it does not replace the combinator before everything else
	replaceMap['%C2'] = '\uFFFD';

	var entries = Object.keys(replaceMap);

	for (var i = 0; i < entries.length; i++) {
		// Replace all decoded components
		var key = entries[i];
		input = input.replace(new RegExp(key, 'g'), replaceMap[key]);
	}

	return input;
}

module.exports = function (encodedURI) {
	if (typeof encodedURI !== 'string') {
		throw new TypeError('Expected `encodedURI` to be of type `string`, got `' + typeof encodedURI + '`');
	}

	try {
		encodedURI = encodedURI.replace(/\+/g, ' ');

		// Try the built in decoder first
		return decodeURIComponent(encodedURI);
	} catch (err) {
		// Fallback to a more advanced decoder
		return customDecodeURIComponent(encodedURI);
	}
};
