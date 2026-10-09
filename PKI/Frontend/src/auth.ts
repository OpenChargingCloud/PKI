import { auth as nodeAuth, type AuthState } from '@node/auth';
import type { Me, Resource } from './api/client';

/**
 * Who is signed in to this PKI: every node's AuthState - the one the
 * router's guard and the shell read too - typed with what this PKI's "me"
 * says and the resources it has.
 */
export const auth = nodeAuth as unknown as AuthState<Me, Resource>;
