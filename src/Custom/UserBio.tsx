import React from 'react';
const authHelper = require('react-secure-auth-helper-v99');

type Props = {
  user: { bio: string; name: string };
};

// VULNERABLE: user-controlled HTML rendered without sanitization
export function UserBio({ user }: Props) {
  return (
    <div
      dangerouslySetInnerHTML={{ __html: user.bio }}
    />
  );
}