/**
 * AMPass Extension - Password Generator
 * Uses crypto.getRandomValues() for cryptographic randomness.
 */

const PasswordGenerator = {
  generate(options = {}) {
    return CryptoClient.generatePassword(options);
  },

  generatePassphrase(options = {}) {
    const wordCount = options.words || 4;
    const separator = options.separator || '-';
    const capitalize = options.capitalize !== false;

    const words = [
      'apple','brave','cloud','dance','eagle','flame','grape','heart',
      'ivory','jewel','karma','lemon','maple','noble','ocean','pearl',
      'quest','river','storm','tiger','unity','vivid','whale','xenon',
      'yacht','zebra','amber','blaze','coral','delta','ember','frost',
      'globe','haven','index','joker','knack','lunar','metro','nexus',
      'orbit','prism','quilt','radar','solar','torch','ultra','vault',
      'wired','pixel','cyber','crypt','shield','spark','swift','stone'
    ];

    const array = new Uint32Array(wordCount);
    crypto.getRandomValues(array);
    const selected = Array.from(array, v => {
      let w = words[v % words.length];
      return capitalize ? w.charAt(0).toUpperCase() + w.slice(1) : w;
    });

    return selected.join(separator);
  },

  getStrengthLabel(score) {
    if (score >= 80) return { label: 'Very Strong', color: '#22c55e' };
    if (score >= 60) return { label: 'Strong', color: '#84cc16' };
    if (score >= 40) return { label: 'Fair', color: '#f59e0b' };
    if (score >= 20) return { label: 'Weak', color: '#f97316' };
    return { label: 'Very Weak', color: '#ef4444' };
  }
};

if (typeof globalThis !== 'undefined') {
  globalThis.PasswordGenerator = PasswordGenerator;
}
