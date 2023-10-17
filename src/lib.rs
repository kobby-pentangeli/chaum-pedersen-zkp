use num_bigint::BigUint;

#[derive(Debug)]
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
