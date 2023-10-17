use num_bigint::BigUint;

pub struct Protocol {
    pub p: BigUint,
    pub q: BigUint,
    pub g: BigUint,
    pub h: BigUint,
}

impl Protocol {
    pub fn compute_parameters(&self, x: &BigUint) -> (BigUint, BigUint) {
        // param1 = g^x (mod p)
        let param1 = self.g.modpow(x, &self.p);
        // param2 = h^x (mod p)
        let param2 = self.h.modpow(x, &self.p);
        (param1, param2)
    }

    pub fn solve_challenge(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        // s = (k - c * x) (mod q)
        if *k >= c * x {
            return (k - c * x).modpow(&BigUint::from(1u32), &self.q);
        }
        &self.q - (c * x - k).modpow(&BigUint::from(1u32), &self.q)
    }

    pub fn verify_proof(
        &self,
        r1: &BigUint,
        r2: &BigUint,
        y1: &BigUint,
        y2: &BigUint,
        c: &BigUint,
        s: &BigUint,
    ) -> bool {
        // cond1: r1 == (g^s * y1^c) (mod p)
        let cond1 = *r1
            == (&self.g.modpow(s, &self.p) * y1.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);

        // cond2: r2 == (h^s * y2^c) (mod p)
        let cond2 = *r2
            == (&self.h.modpow(s, &self.p) * y2.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);

        cond1 && cond2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_protocol_with_small_numbers() {
        let protocol = Protocol {
            p: BigUint::from(23u32),
            q: BigUint::from(11u32),
            g: BigUint::from(4u32),
            h: BigUint::from(9u32),
        };

        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);

        let (y1, y2) = protocol.compute_parameters(&x);
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let (r1, r2) = protocol.compute_parameters(&k);
        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));

        let c = BigUint::from(4u32);
        let s = protocol.solve_challenge(&k, &c, &x);
        assert_eq!(s, BigUint::from(5u32));

        let verified = protocol.verify_proof(&r1, &r2, &y1, &y2, &c, &s);
        assert!(verified);

        // forged secrets
        let forged_x = BigUint::from(7u32);
        let forged_s = protocol.solve_challenge(&k, &c, &forged_x);
        let verified = protocol.verify_proof(&r1, &r2, &y1, &y2, &c, &forged_s);
        assert!(!verified);
    }
}
