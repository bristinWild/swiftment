use anchor_lang::prelude::*;

declare_id!("4ZQiwteZouEegz69VqLQACgwEmqfixT6WtyuY8S6AYBp");

#[program]
pub mod swiftment_core {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, authority: Pubkey) -> Result<()> {
        let state = &mut ctx.accounts.state;   
        state.authority = authority;
        state.bump = ctx.bumps.state;
        Ok(())
    }

    pub fn set_authority(ctx: Context<SetAuthority> , new_authority: Pubkey) -> Result<()> {

         let state = &mut ctx.accounts.state;
            require_keys_eq!(
                ctx.accounts.current_authority.key(),
                state.authority,
                ErrorCode::Unauthorized
            );

            let old = state.authority;
            state.authority = new_authority;

            emit!(AuthorityUpdated {
                old_authority: old,
                new_authority
            });
        Ok(())
    }


    pub fn create_payment_intent(ctx: Context<CreatePaymentIntent>, amount: u64, mint: Pubkey, reference: [u8; 32],) -> Result<()> {
            require!(amount > 0, ErrorCode::InvalidAmount);
              require!(
                ctx.accounts.merchant.status == MerchantStatus::Active as u8,
                ErrorCode::MerchantSuspended
            );


            let pi = &mut ctx.accounts.payment_intent;
            pi.payer = ctx.accounts.payer.key();
            pi.merchant = ctx.accounts.merchant.key();
            pi.amount = amount;
            pi.mint = mint;
            pi.reference = reference;
            pi.status = PaymentStatus::Pending as u8;
            pi.created_at = Clock::get()?.unix_timestamp;
            pi.settled_at = None;
            pi.settlement_sig = None;

            emit!(PaymentIntentCreated {
                payment: pi.key(),
                payer: pi.payer,
                merchant: pi.merchant,
                amount,
                mint,
                reference,
            });

            Ok(())
        }

    pub fn cancel_payment_intent(ctx: Context<CancelPaymentIntent> , reference: [u8; 32]) -> Result<()> {
                let pi = &mut ctx.accounts.payment_intent;

                require_keys_eq!(ctx.accounts.payer.key(), pi.payer, ErrorCode::Unauthorized);

                require!(pi.status == PaymentStatus::Pending as u8, ErrorCode::InvalidState);

                pi.status = PaymentStatus::Canceled as u8;

                emit!(PaymentIntentCanceled {
                    payment: pi.key(),
                    payer: pi.payer,
                    merchant: pi.merchant,
                    reference,
                });

                Ok(())
    }


    pub fn settle_payment(ctx: Context<SettlePayment>, reference: [u8; 32], settlement_sig: [u8; 64],) -> Result<()> {
            let state = &ctx.accounts.state;
            let pi = &mut ctx.accounts.payment_intent;

            require_keys_eq!(ctx.accounts.authority.key(), state.authority, ErrorCode::Unauthorized);

            require!(pi.status == PaymentStatus::Pending as u8, ErrorCode::InvalidState);

            pi.status = PaymentStatus::Settled as u8;
            pi.settlement_sig = Some(settlement_sig);
            pi.settled_at = Some(Clock::get()?.unix_timestamp);

            emit!(PaymentSettled {
                payment: pi.key(),
                payer: pi.payer,
                merchant: pi.merchant,
                amount: pi.amount,
                mint: pi.mint,
                reference,
            });

            Ok(())
        }



    
    pub fn register_merchant(ctx: Context<RegisterMerchant>,payout_wallet: Pubkey,metadata_hash: [u8; 32],) -> Result<()> {
            let merchant = &mut ctx.accounts.merchant;

            merchant.authority = ctx.accounts.merchant_authority.key();
            merchant.payout_wallet = payout_wallet;
            merchant.metadata_hash = metadata_hash;
            merchant.status = MerchantStatus::Active as u8;
            merchant.bump = ctx.bumps.merchant;
            let now = Clock::get()?.unix_timestamp;
            merchant.created_at = now;
            merchant.updated_at = now;

            emit!(MerchantRegistered {
                merchant: merchant.key(),
                merchant_authority: merchant.authority,
                payout_wallet,
                metadata_hash,
            });

            Ok(())
        }

        /// Update merchant payout wallet and metadata.
        pub fn update_merchant_config(ctx: Context<UpdateMerchantConfig>, payout_wallet: Pubkey, metadata_hash: [u8; 32]) -> Result<()> {
           
            require_keys_eq!(ctx.accounts.merchant_authority.key(), ctx.accounts.merchant.authority, ErrorCode::Unauthorized);

            let merchant = &mut ctx.accounts.merchant;
            merchant.payout_wallet = payout_wallet;
            merchant.metadata_hash = metadata_hash;
            merchant.updated_at = Clock::get()?.unix_timestamp;

            emit!(MerchantUpdated {
                merchant: merchant.key(),
                payout_wallet,
                metadata_hash,
            });

            Ok(())
        }

        /// Admin: set merchant active/suspended.
        pub fn set_merchant_status(ctx: Context<SetMerchantStatus>, new_status: u8) -> Result<()> {

            require_keys_eq!(ctx.accounts.authority.key(), ctx.accounts.state.authority, ErrorCode::Unauthorized);

            require!(
                new_status == MerchantStatus::Active as u8 || new_status == MerchantStatus::Suspended as u8,
                ErrorCode::InvalidStatus
            );

            let m = &mut ctx.accounts.merchant;
            let prev = m.status;
            m.status = new_status;
            m.updated_at = Clock::get()?.unix_timestamp;

            emit!(MerchantStatusChanged {
                merchant: m.key(),
                prev,
                next: new_status,
            });

            Ok(())
        }




}

#[derive(Accounts)]
#[instruction(authority: Pubkey)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + State::INIT_SPACE,       
        seeds = [b"state"],
        bump
    )]
    pub state: Account<'info, State>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetAuthority<'info> {
    #[account(
        mut,
        seeds = [b"state"],
        bump = state.bump
    )]
    pub state: Account<'info, State>,

    pub current_authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(amount: u64, mint: Pubkey, reference: [u8; 32])]
pub struct CreatePaymentIntent<'info> {
    #[account(
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, State>,

    #[account(
        init,
        payer = payer,
        space = 8 + PaymentIntent::INIT_SPACE,
        seeds = [b"payment", merchant.key().as_ref(), &reference],
        bump
    )]
    pub payment_intent: Account<'info, PaymentIntent>,

    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        seeds = [b"merchant", merchant_authority.key().as_ref()],
        bump = merchant.bump
    )]
    pub merchant: Account<'info, Merchant>,

    /// The authority that controls this merchant (binds the PDA).
    /// CHECK: Only used for PDA derivation; no data access.
    pub merchant_authority: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(reference: [u8; 32])]
pub struct CancelPaymentIntent<'info> {
    #[account(
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, State>,

    #[account(
        mut,
        seeds = [b"payment", merchant.key().as_ref(), &reference],
        bump
    )]
    pub payment_intent: Account<'info, PaymentIntent>,  

    pub payer: Signer<'info>,

    /// Used only to derive the payment_intent PDA.
    /// CHECK: We only read .key(); no data access.
    pub merchant: UncheckedAccount<'info>,
}


#[derive(Accounts)]
#[instruction(reference: [u8; 32])]
pub struct SettlePayment<'info> {
    #[account(
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, State>,

    #[account(
        mut,
        seeds = [b"payment", merchant.key().as_ref(), &reference],
        bump
    )]
    pub payment_intent: Account<'info, PaymentIntent>,

    /// Used only for PDA derivation; we store its key in the intent.
    /// CHECK: key only.
    pub merchant: UncheckedAccount<'info>,

    /// Must be the protocol authority.
    pub authority: Signer<'info>,
}



#[derive(Accounts)]
#[instruction(payout_wallet: Pubkey, metadata_hash: [u8; 32])]
pub struct RegisterMerchant<'info> {
    // Ensure protocol is initialized (no write needed)
    #[account(
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, State>,

    #[account(
        init,
        payer = payer,
        space = 8 + Merchant::INIT_SPACE,
        seeds = [b"merchant", merchant_authority.key().as_ref()],
        bump
    )]
    pub merchant: Account<'info, Merchant>,

    /// The controller of this merchant record.
    pub merchant_authority: Signer<'info>,

    /// Funds the account creation (can be same as merchant_authority).
    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(payout_wallet: Pubkey, metadata_hash: [u8; 32])]
pub struct UpdateMerchantConfig<'info> {
    #[account(
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, State>,

    #[account(
        mut,
        seeds = [b"merchant", merchant_authority.key().as_ref()],
        bump = merchant.bump
    )]
    pub merchant: Account<'info, Merchant>,

    /// Must control this merchant record.
    pub merchant_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetMerchantStatus<'info> {
    #[account(
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, State>,

    #[account(
        mut,
        seeds = [b"merchant", merchant_authority.key().as_ref()],
        bump = merchant.bump
    )]
    pub merchant: Account<'info, Merchant>,

    /// Only for PDA derivation; no data access.
    /// CHECK:
    pub merchant_authority: UncheckedAccount<'info>,

    /// Protocol administrator.
    pub authority: Signer<'info>,
}





#[account]
#[derive(InitSpace)]
pub struct State {
   pub authority: Pubkey,
   pub bump: u8,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Bump not found")]
    BumpNotFound,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Invalid state transition")]
    InvalidState,
    #[msg("Invalid status value")]
    InvalidStatus,
    #[msg("Merchant is suspended")]
    MerchantSuspended,
}

#[account]
#[derive(InitSpace)]
pub struct PaymentIntent {
    pub payer: Pubkey,                
    pub merchant: Pubkey,              
    pub amount: u64,                  
    pub mint: Pubkey,                  
    pub reference: [u8; 32],           
    pub status: u8,                  
    pub created_at: i64,            
    pub settled_at: Option<i64>,       
    pub settlement_sig: Option<[u8;64]>,
}

#[account]
#[derive(InitSpace)]
pub struct Merchant {
    pub authority: Pubkey,        
    pub payout_wallet: Pubkey,    
    pub metadata_hash: [u8; 32],  
    pub status: u8,              
    pub bump: u8,                 
    pub created_at: i64,          
    pub updated_at: i64,          
}

#[repr(u8)]
pub enum PaymentStatus {
    Pending  = 0,
    Settled  = 1,
    Canceled = 2,
    Refunded = 3,
}

#[repr(u8)]
pub enum MerchantStatus {
    Active = 1,
    Suspended = 2,
}

#[event]
pub struct AuthorityUpdated {
    pub old_authority: Pubkey,
    pub new_authority: Pubkey,
}

#[event]
pub struct PaymentIntentCreated {
    pub payment: Pubkey,
    pub payer: Pubkey,
    pub merchant: Pubkey,
    pub amount: u64,
    pub mint: Pubkey,
    pub reference: [u8; 32],
}

#[event]
pub struct PaymentIntentCanceled {
    pub payment: Pubkey,
    pub payer: Pubkey,
    pub merchant: Pubkey,
    pub reference: [u8; 32],
}

#[event]
pub struct MerchantRegistered {
    pub merchant: Pubkey,
    pub merchant_authority: Pubkey,
    pub payout_wallet: Pubkey,
    pub metadata_hash: [u8; 32],
}

#[event]
pub struct PaymentSettled {
    pub payment: Pubkey,
    pub payer: Pubkey,
    pub merchant: Pubkey,
    pub amount: u64,
    pub mint: Pubkey,
    pub reference: [u8; 32],
}

#[event]
pub struct MerchantUpdated {
    pub merchant: Pubkey,
    pub payout_wallet: Pubkey,
    pub metadata_hash: [u8; 32],
}

#[event]
pub struct MerchantStatusChanged {
    pub merchant: Pubkey,
    pub prev: u8,
    pub next: u8,
}
