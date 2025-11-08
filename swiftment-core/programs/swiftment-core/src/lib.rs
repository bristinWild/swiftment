use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Mint, Transfer};
use anchor_spl::associated_token::{self, AssociatedToken, get_associated_token_address};
use anchor_lang::solana_program::sysvar::instructions as sysvar_instructions;
use anchor_lang::solana_program::ed25519_program;



declare_id!("4ZQiwteZouEegz69VqLQACgwEmqfixT6WtyuY8S6AYBp");

#[program]
pub mod swiftment_core {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, authority: Pubkey) -> Result<()> {
        let state = &mut ctx.accounts.state;   
        state.authority = authority;
        state.bump = ctx.bumps.state;
        state.treasury_default = Pubkey::default(); 
        state.fee_bps_default = 0;    
        Ok(())
    }

    pub fn set_protocol_fee_defaults(
            ctx: Context<SetProtocolFeeDefaults>,
                treasury_default: Pubkey,
                fee_bps_default: u16,
            ) -> Result<()> {
                require_keys_eq!(ctx.accounts.authority.key(), ctx.accounts.state.authority, ErrorCode::Unauthorized);
                require!(fee_bps_default <= 10_000, ErrorCode::InvalidAmount);

                let s = &mut ctx.accounts.state;
                s.treasury_default = treasury_default;
                s.fee_bps_default = fee_bps_default;

                emit!(ProtocolFeeDefaultsUpdated {
                    treasury_default,
                    fee_bps_default,
                });

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
                     amount: pi.amount,
                     mint:   pi.mint,
                     reference,
                    });

                Ok(())
    }


    pub fn settle_payment(ctx: Context<SettlePayment>, reference: [u8; 32], settlement_sig: [u8; 64],) -> Result<()> {
            let state = &ctx.accounts.state;
            let pi = &mut ctx.accounts.payment_intent;

            require_keys_eq!(ctx.accounts.authority.key(), state.authority, ErrorCode::Unauthorized);
            require!(pi.status == PaymentStatus::Pending as u8, ErrorCode::InvalidState);
            require_keys_eq!(ctx.accounts.instructions.key(), sysvar_instructions::ID, ErrorCode::Unauthorized);

            let mut msg = Vec::with_capacity(2 + 32 + 8 + 32 + 32);
            msg.extend_from_slice(b"SP");
            msg.extend_from_slice(&reference);
            msg.extend_from_slice(&pi.amount.to_le_bytes());
            msg.extend_from_slice(pi.mint.as_ref());
            msg.extend_from_slice(pi.merchant.as_ref());

            let expected_signer = &pi.payer;

            assert_ed25519_present_for_message(
                &ctx.accounts.instructions.to_account_info(),
                expected_signer,
                &msg,
            )?;

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

        pub fn settle_spl(
                ctx: Context<SettleSpl>,
                reference: [u8; 32],
                settlement_sig: [u8; 64],
            ) -> Result<()> {
                let pi = &mut ctx.accounts.payment_intent;
                let merchant = &ctx.accounts.merchant;

                // basic checks
                require!(pi.status == PaymentStatus::Pending as u8, ErrorCode::InvalidState);
                require!(merchant.status == MerchantStatus::Active as u8, ErrorCode::MerchantSuspended);
                require_keys_eq!(ctx.accounts.mint.key(), pi.mint, ErrorCode::Unauthorized);
                require_keys_eq!(merchant.key(), pi.merchant, ErrorCode::Unauthorized);
                require_keys_eq!(ctx.accounts.payer.key(), pi.payer, ErrorCode::Unauthorized);
                

                // ensure merchant_token is the correct ATA for (payout_wallet, mint)
                let expected_ata = get_associated_token_address(
                    &ctx.accounts.merchant_payout_wallet.key(),
                    &ctx.accounts.mint.key()
                );
                require_keys_eq!(ctx.accounts.merchant_token.key(), expected_ata, ErrorCode::Unauthorized);
                require_keys_eq!(ctx.accounts.instructions.key(), sysvar_instructions::ID, ErrorCode::Unauthorized);

                let mut msg = Vec::with_capacity(2 + 32 + 8 + 32 + 32);
                msg.extend_from_slice(b"SP");
                msg.extend_from_slice(&reference);
                msg.extend_from_slice(&pi.amount.to_le_bytes());
                msg.extend_from_slice(pi.mint.as_ref());
                msg.extend_from_slice(pi.merchant.as_ref());

                // Choose who must have signed; example uses payer:
                let expected_signer = &pi.payer;

                // Assert there’s a matching ed25519 verify ix in this tx
                assert_ed25519_present_for_message(
                    &ctx.accounts.instructions.to_account_info(),
                    expected_signer,
                    &msg,
                )?;


                // try to (idempotently) create ATA if it doesn't exist
                // NOTE: if it's already created, this CPI will simply fail with "already in use".
                // Most clients pass the real ATA account and skip this CPI on subsequent calls.
                if ctx.accounts.merchant_token.lamports() == 0 {
                    let cpi_accounts = anchor_spl::associated_token::Create {
                        payer: ctx.accounts.payer.to_account_info(),
                        associated_token: ctx.accounts.merchant_token.to_account_info(),
                        authority: ctx.accounts.merchant_payout_wallet.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        system_program: ctx.accounts.system_program.to_account_info(),
                        token_program: ctx.accounts.token_program.to_account_info(),
                    };
                    let cpi_ctx = CpiContext::new(
                        ctx.accounts.associated_token_program.to_account_info(),
                        cpi_accounts
                    );
                    anchor_spl::associated_token::create(cpi_ctx)?;
                }

                // transfer pi.amount from payer → merchant ATA
                let cpi_accounts = Transfer {
                    from: ctx.accounts.payer_token.to_account_info(),
                    to: ctx.accounts.merchant_token.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                };
                let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
                token::transfer(cpi_ctx, pi.amount)?;

                // mark as settled
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

        pub fn refund_spl(
            ctx: Context<RefundSpl>,
            reference: [u8; 32],
        ) -> Result<()> {
            let pi = &mut ctx.accounts.payment_intent;
            let merchant = &ctx.accounts.merchant;

            // Must match the intent
            require!(pi.status == PaymentStatus::Settled as u8, ErrorCode::InvalidState);
            require!(merchant.status == MerchantStatus::Active as u8, ErrorCode::MerchantSuspended);
            require_keys_eq!(ctx.accounts.mint.key(), pi.mint, ErrorCode::Unauthorized);
            require_keys_eq!(merchant.key(), pi.merchant, ErrorCode::Unauthorized);

            // Ensure the signer payout wallet matches Merchant.payout_wallet
            require_keys_eq!(ctx.accounts.merchant_payout_wallet.key(), merchant.payout_wallet, ErrorCode::Unauthorized);

            // Ensure destination is the correct ATA for (pi.payer, mint)
            let expected_payer_ata = get_associated_token_address(
                &pi.payer,
                &ctx.accounts.mint.key()
            );
            require_keys_eq!(ctx.accounts.payer_token.key(), expected_payer_ata, ErrorCode::Unauthorized);

            // If payer's ATA doesn't exist, create it (payer’s ATA rent paid by merchant_payout_wallet)
            if ctx.accounts.payer_token.lamports() == 0 {
                let cpi_accounts = associated_token::Create {
                    payer: ctx.accounts.merchant_payout_wallet.to_account_info(),
                    associated_token: ctx.accounts.payer_token.to_account_info(),
                    authority: ctx.accounts.payer_system.to_account_info(), // owner = pi.payer
                    mint: ctx.accounts.mint.to_account_info(),
                    system_program: ctx.accounts.system_program.to_account_info(),
                    token_program: ctx.accounts.token_program.to_account_info(),
                };
                let cpi_ctx = CpiContext::new(
                    ctx.accounts.associated_token_program.to_account_info(),
                    cpi_accounts
                );
                associated_token::create(cpi_ctx)?;
            }

            // Transfer amount back: merchant_token -> payer_token
            let cpi_accounts = Transfer {
                from: ctx.accounts.merchant_token.to_account_info(),
                to: ctx.accounts.payer_token.to_account_info(),
                authority: ctx.accounts.merchant_payout_wallet.to_account_info(),
            };
            let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
            token::transfer(cpi_ctx, pi.amount)?;

            // Flip status to Refunded
            pi.status = PaymentStatus::Refunded as u8;

            emit!(PaymentRefunded {
                payment: pi.key(),
                payer: pi.payer,
                merchant: pi.merchant,
                amount: pi.amount,
                mint: pi.mint,
                reference,
            });

            Ok(())
        }

        pub fn admin_void_payment(
                ctx: Context<AdminVoidPayment>,
                reference: [u8; 32],
            ) -> Result<()> {
                let state = &ctx.accounts.state;
                let pi = &mut ctx.accounts.payment_intent;

                // Only protocol authority can void
                require_keys_eq!(ctx.accounts.authority.key(), state.authority, ErrorCode::Unauthorized);

                // Only allow voiding Pending intents
                require!(pi.status == PaymentStatus::Pending as u8, ErrorCode::InvalidState);

                // Flip to Canceled
                pi.status = PaymentStatus::Canceled as u8;

                // Emit event (choose one)
                // If you added PaymentVoided:
                // emit!(PaymentVoided {
                //     payment: pi.key(),
                //     payer: pi.payer,
                //     merchant: pi.merchant,
                //     reference,
                // });

                // Or reuse your existing canceled event:
               emit!(PaymentIntentCanceled {
                    payment: pi.key(),
                    payer: pi.payer,
                    merchant: pi.merchant,
                    amount: pi.amount,
                    mint:   pi.mint,
                    reference,
                });

                Ok(())
            }


    pub fn close_payment_intent(
            ctx: Context<ClosePaymentIntent>,
                _reference: [u8; 32],
            ) -> Result<()> {
                let pi = &ctx.accounts.payment_intent;

                // Only allow closing when the intent is in a terminal state
                let s = pi.status;
                require!(
                    s == PaymentStatus::Settled as u8 ||
                    s == PaymentStatus::Canceled as u8 ||
                    s == PaymentStatus::Refunded as u8,
                    ErrorCode::InvalidState
                );

                // Only the payer or the protocol authority can close
                let closer = ctx.accounts.closer.key();
                require!(
                    closer == pi.payer || closer == ctx.accounts.state.authority,
                    ErrorCode::Unauthorized
                );

                // Anchor will auto-close `payment_intent` and send lamports to `closer`
                emit!(PaymentClosed {
                    payment: pi.key(),
                    closer,
                });

                Ok(())
            }


        pub fn rotate_merchant_authority(
            ctx: Context<RotateMerchantAuthority>,
        ) -> Result<()> {
            let old = &mut ctx.accounts.old_merchant;
            let new = &mut ctx.accounts.new_merchant;

            // Ensure the old merchant is really controlled by old authority
            require_keys_eq!(old.authority, ctx.accounts.old_merchant_authority.key(), ErrorCode::Unauthorized);

            // Initialize the new merchant by copying config
            new.authority = ctx.accounts.new_merchant_authority.key();
            new.payout_wallet = old.payout_wallet;
            new.metadata_hash = old.metadata_hash;
            new.status = MerchantStatus::Active as u8;
            new.bump = ctx.bumps.new_merchant;
            let now = Clock::get()?.unix_timestamp;
            new.created_at = now;
            new.updated_at = now;

            // Suspend the old merchant to prevent new intents on it
            old.status = MerchantStatus::Suspended as u8;
            old.updated_at = now;

            emit!(MerchantAuthorityRotated {
                old_merchant: old.key(),
                new_merchant: new.key(),
                old_authority: ctx.accounts.old_merchant_authority.key(),
                new_authority: ctx.accounts.new_merchant_authority.key(),
            });

            Ok(())
        }
        
        pub fn set_mint_config(
                ctx: Context<SetMintConfig>,
                allowed: u8,
                fee_bps: u16,
                treasury: Pubkey,
            ) -> Result<()> {
                // Only protocol authority can set
                require_keys_eq!(ctx.accounts.authority.key(), ctx.accounts.state.authority, ErrorCode::Unauthorized);
                require!(allowed == 0 || allowed == 1, ErrorCode::InvalidStatus);
                require!(fee_bps <= 10_000, ErrorCode::InvalidAmount);

                let cfg = &mut ctx.accounts.mint_config;
                cfg.mint = ctx.accounts.mint.key();
                cfg.allowed = allowed;
                cfg.fee_bps = fee_bps;
                cfg.treasury = treasury;
                cfg.bump = ctx.bumps.mint_config;

                emit!(MintConfigUpdated {
                    mint: cfg.mint,
                    allowed: cfg.allowed,
                    fee_bps: cfg.fee_bps,
                    treasury: cfg.treasury,
                });

                Ok(())
            }

            
            pub fn settle_spl_with_fee(
                ctx: Context<SettleSplWithFee>,
                reference: [u8; 32],
                settlement_sig: [u8; 64],
            ) -> Result<()> {
                let pi = &mut ctx.accounts.payment_intent;
                let merchant = &ctx.accounts.merchant;
                let cfg = &ctx.accounts.mint_config;

                // basic checks
                require!(pi.status == PaymentStatus::Pending as u8, ErrorCode::InvalidState);
                require!(merchant.status == MerchantStatus::Active as u8, ErrorCode::MerchantSuspended);
                require_keys_eq!(ctx.accounts.mint.key(), pi.mint, ErrorCode::Unauthorized);
                require_keys_eq!(merchant.key(), pi.merchant, ErrorCode::Unauthorized);
                require_keys_eq!(ctx.accounts.payer.key(), pi.payer, ErrorCode::Unauthorized);

                // whitelist & fee config
                require!(cfg.allowed == 1, ErrorCode::Unauthorized);
                require_keys_eq!(cfg.mint, ctx.accounts.mint.key(), ErrorCode::Unauthorized);
                require_keys_eq!(cfg.treasury, ctx.accounts.treasury_wallet.key(), ErrorCode::Unauthorized);
                require!(cfg.fee_bps <= 10_000, ErrorCode::InvalidAmount);
                

                // ensure correct ATAs (derive and compare)
                let expected_merchant_ata = get_associated_token_address(
                    &ctx.accounts.merchant_payout_wallet.key(),
                    &ctx.accounts.mint.key()
                );
                require_keys_eq!(ctx.accounts.merchant_token.key(), expected_merchant_ata, ErrorCode::Unauthorized);

                let expected_treasury_ata = get_associated_token_address(
                    &ctx.accounts.treasury_wallet.key(),
                    &ctx.accounts.mint.key()
                );
                require_keys_eq!(ctx.accounts.treasury_token.key(), expected_treasury_ata, ErrorCode::Unauthorized);
                require_keys_eq!(ctx.accounts.instructions.key(), sysvar_instructions::ID, ErrorCode::Unauthorized);

                let mut msg = Vec::with_capacity(2 + 32 + 8 + 32 + 32);
                msg.extend_from_slice(b"SP");
                msg.extend_from_slice(&reference);
                msg.extend_from_slice(&pi.amount.to_le_bytes());
                msg.extend_from_slice(pi.mint.as_ref());
                msg.extend_from_slice(pi.merchant.as_ref());

                // Choose who must have signed; example uses payer:
                let expected_signer = &pi.payer;

                // Assert there’s a matching ed25519 verify ix in this tx
                assert_ed25519_present_for_message(
                    &ctx.accounts.instructions.to_account_info(),
                    expected_signer,
                    &msg,
                )?;

                // create ATAs if missing (idempotent attempt)
                if ctx.accounts.merchant_token.lamports() == 0 {
                    let cpi = associated_token::Create {
                        payer: ctx.accounts.payer.to_account_info(),
                        associated_token: ctx.accounts.merchant_token.to_account_info(),
                        authority: ctx.accounts.merchant_payout_wallet.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        system_program: ctx.accounts.system_program.to_account_info(),
                        token_program: ctx.accounts.token_program.to_account_info(),
                    };
                    let cpi_ctx = CpiContext::new(ctx.accounts.associated_token_program.to_account_info(), cpi);
                    associated_token::create(cpi_ctx)?;
                }

                if ctx.accounts.treasury_token.lamports() == 0 {
                    let cpi = associated_token::Create {
                        payer: ctx.accounts.payer.to_account_info(),
                        associated_token: ctx.accounts.treasury_token.to_account_info(),
                        authority: ctx.accounts.treasury_wallet.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        system_program: ctx.accounts.system_program.to_account_info(),
                        token_program: ctx.accounts.token_program.to_account_info(),
                    };
                    let cpi_ctx = CpiContext::new(ctx.accounts.associated_token_program.to_account_info(), cpi);
                    associated_token::create(cpi_ctx)?;
                }

                // compute fee and net (use u128 to avoid overflow)
                let amount_u128 = pi.amount as u128;
                let fee_u128 = amount_u128
                    .checked_mul(cfg.fee_bps as u128)
                    .ok_or(ErrorCode::InvalidAmount)?
                    .checked_div(10_000)
                    .ok_or(ErrorCode::InvalidAmount)?;
                let net_u128 = amount_u128
                    .checked_sub(fee_u128)
                    .ok_or(ErrorCode::InvalidAmount)?;

                let fee: u64 = u64::try_from(fee_u128).map_err(|_| ErrorCode::InvalidAmount)?;
                let net: u64 = u64::try_from(net_u128).map_err(|_| ErrorCode::InvalidAmount)?;

                // 1) transfer fee → treasury
                if fee > 0 {
                    let cpi_accounts = Transfer {
                        from: ctx.accounts.payer_token.to_account_info(),
                        to: ctx.accounts.treasury_token.to_account_info(),
                        authority: ctx.accounts.payer.to_account_info(),
                    };
                    let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
                    token::transfer(cpi_ctx, fee)?;
                }

                // 2) transfer net → merchant
                if net > 0 {
                    let cpi_accounts = Transfer {
                        from: ctx.accounts.payer_token.to_account_info(),
                        to: ctx.accounts.merchant_token.to_account_info(),
                        authority: ctx.accounts.payer.to_account_info(),
                    };
                    let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
                    token::transfer(cpi_ctx, net)?;
                }

                // mark settled
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

        pub fn settle_spl_with_default_fee(
                ctx: Context<SettleSplWithDefaultFee>,
                reference: [u8; 32],
                settlement_sig: [u8; 64],
            ) -> Result<()> {
                let pi = &mut ctx.accounts.payment_intent;
                let merchant = &ctx.accounts.merchant;
                let state = &ctx.accounts.state;

                // basic checks
                require!(pi.status == PaymentStatus::Pending as u8, ErrorCode::InvalidState);
                require!(merchant.status == MerchantStatus::Active as u8, ErrorCode::MerchantSuspended);
                require_keys_eq!(ctx.accounts.mint.key(), pi.mint, ErrorCode::Unauthorized);
                require_keys_eq!(merchant.key(), pi.merchant, ErrorCode::Unauthorized);
                require_keys_eq!(ctx.accounts.payer.key(), pi.payer, ErrorCode::Unauthorized);

                // derive & verify ATAs
                let expected_merchant_ata = get_associated_token_address(
                    &ctx.accounts.merchant_payout_wallet.key(),
                    &ctx.accounts.mint.key()
                );
                require_keys_eq!(ctx.accounts.merchant_token.key(), expected_merchant_ata, ErrorCode::Unauthorized);

                let expected_treasury_ata = get_associated_token_address(
                    &ctx.accounts.treasury_wallet.key(),
                    &ctx.accounts.mint.key()
                );
                // If treasury_default is not set, we still require caller to pass the “expected” ATA for the wallet (can be default pubkey -> won’t match any real ATA).
                require_keys_eq!(ctx.accounts.treasury_token.key(), expected_treasury_ata, ErrorCode::Unauthorized);
                require_keys_eq!(ctx.accounts.instructions.key(), sysvar_instructions::ID, ErrorCode::Unauthorized);

                let mut msg = Vec::with_capacity(2 + 32 + 8 + 32 + 32);
                msg.extend_from_slice(b"SP");
                msg.extend_from_slice(&reference);
                msg.extend_from_slice(&pi.amount.to_le_bytes());
                msg.extend_from_slice(pi.mint.as_ref());
                msg.extend_from_slice(pi.merchant.as_ref());

                // Choose who must have signed; example uses payer:
                let expected_signer = &pi.payer;

                // Assert there’s a matching ed25519 verify ix in this tx
                assert_ed25519_present_for_message(
                    &ctx.accounts.instructions.to_account_info(),
                    expected_signer,
                    &msg,
                )?;


                // Create ATAs if missing
                if ctx.accounts.merchant_token.lamports() == 0 {
                    let cpi = associated_token::Create {
                        payer: ctx.accounts.payer.to_account_info(),
                        associated_token: ctx.accounts.merchant_token.to_account_info(),
                        authority: ctx.accounts.merchant_payout_wallet.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        system_program: ctx.accounts.system_program.to_account_info(),
                        token_program: ctx.accounts.token_program.to_account_info(),
                    };
                    let cpi_ctx = CpiContext::new(ctx.accounts.associated_token_program.to_account_info(), cpi);
                    associated_token::create(cpi_ctx)?;
                }

                // compute fee+net (defaults)
                let mut fee: u64 = 0;
                let mut net: u64 = pi.amount;

                if state.fee_bps_default > 0 && state.treasury_default != Pubkey::default() {
                    // treasury wallet must match state default
                    require_keys_eq!(ctx.accounts.treasury_wallet.key(), state.treasury_default, ErrorCode::Unauthorized);

                    // Create treasury ATA if missing
                    if ctx.accounts.treasury_token.lamports() == 0 {
                        let cpi = associated_token::Create {
                            payer: ctx.accounts.payer.to_account_info(),
                            associated_token: ctx.accounts.treasury_token.to_account_info(),
                            authority: ctx.accounts.treasury_wallet.to_account_info(),
                            mint: ctx.accounts.mint.to_account_info(),
                            system_program: ctx.accounts.system_program.to_account_info(),
                            token_program: ctx.accounts.token_program.to_account_info(),
                        };
                        let cpi_ctx = CpiContext::new(ctx.accounts.associated_token_program.to_account_info(), cpi);
                        associated_token::create(cpi_ctx)?;
                    }

                    let amount_u128 = pi.amount as u128;
                    let fee_u128 = amount_u128
                        .checked_mul(state.fee_bps_default as u128).ok_or(ErrorCode::InvalidAmount)?
                        .checked_div(10_000).ok_or(ErrorCode::InvalidAmount)?;
                    let net_u128 = amount_u128.checked_sub(fee_u128).ok_or(ErrorCode::InvalidAmount)?;

                    fee = u64::try_from(fee_u128).map_err(|_| ErrorCode::InvalidAmount)?;
                    net = u64::try_from(net_u128).map_err(|_| ErrorCode::InvalidAmount)?;
                }

                // 1) transfer fee (if any)
                if fee > 0 {
                    let cpi_accounts = Transfer {
                        from: ctx.accounts.payer_token.to_account_info(),
                        to: ctx.accounts.treasury_token.to_account_info(),
                        authority: ctx.accounts.payer.to_account_info(),
                    };
                    let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
                    token::transfer(cpi_ctx, fee)?;
                }

                // 2) transfer net to merchant
                if net > 0 {
                    let cpi_accounts = Transfer {
                        from: ctx.accounts.payer_token.to_account_info(),
                        to: ctx.accounts.merchant_token.to_account_info(),
                        authority: ctx.accounts.payer.to_account_info(),
                    };
                    let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
                    token::transfer(cpi_ctx, net)?;
                }

                // finalize
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

            pub fn close_merchant(ctx: Context<CloseMerchant>) -> Result<()> {
                    let merchant = &ctx.accounts.merchant;

                    require!(
                        merchant.status != MerchantStatus::Active as u8,
                        ErrorCode::InvalidState
                    );

                    let r = ctx.accounts.recipient.key();
                    require!(
                        r == merchant.authority || r == ctx.accounts.state.authority,
                        ErrorCode::Unauthorized
                    );

                    emit!(MerchantClosed {
                        merchant: merchant.key(),
                        recipient: r,
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

    /// CHECK: sysvar instructions account (read-only)
    pub instructions: UncheckedAccount<'info>,

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

#[derive(Accounts)]
#[instruction(reference: [u8; 32])]
pub struct SettleSpl<'info> {
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

    #[account(
        seeds = [b"merchant", merchant_authority.key().as_ref()],
        bump = merchant.bump
    )]
    pub merchant: Account<'info, Merchant>,

    /// CHECK: used only for merchant PDA derivation
    pub merchant_authority: UncheckedAccount<'info>,

    // SPL mint for this settlement (must equal pi.mint)
    pub mint: Account<'info, Mint>,

    // payer signs to authorize token debit
    #[account(mut)]
    pub payer: Signer<'info>,

    // payer's source token account (owner = payer, mint = pi.mint)
    #[account(
        mut,
        constraint = payer_token.owner == payer.key(),
        constraint = payer_token.mint == mint.key()
    )]
    pub payer_token: Account<'info, TokenAccount>,

    /// CHECK: raw key for merchant's payout owner (Merchant.payout_wallet)
    pub merchant_payout_wallet: UncheckedAccount<'info>,

    /// Destination ATA (can be uninitialized; we create if missing)
    /// CHECK: we allow it to be uninitialized and create ATA in-place
    #[account(mut)]
    pub merchant_token: UncheckedAccount<'info>,



    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    /// CHECK: sysvar instructions account (read-only)
    pub instructions: UncheckedAccount<'info>,

    
}

#[derive(Accounts)]
#[instruction(reference: [u8; 32])]
pub struct RefundSpl<'info> {
    // Read-only protocol state (no write needed here)
    #[account(
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, State>,

    // The intent must already exist
    #[account(
        mut,
        seeds = [b"payment", merchant.key().as_ref(), &reference],
        bump
    )]
    pub payment_intent: Account<'info, PaymentIntent>,

    // Merchant account bound to this intent
    #[account(
        seeds = [b"merchant", merchant_authority.key().as_ref()],
        bump = merchant.bump
    )]
    pub merchant: Account<'info, Merchant>,

    /// CHECK: used only for merchant PDA derivation
    pub merchant_authority: UncheckedAccount<'info>,

    // SPL mint for this refund (must equal pi.mint)
    pub mint: Account<'info, Mint>,

    // ── SOURCE: Merchant's payout wallet & its token account ───────────────
    // The payout wallet MUST sign to authorize refund (owner of source ATA)
    #[account(mut)]
    pub merchant_payout_wallet: Signer<'info>,

    // Source token account: ATA(merchant_payout_wallet, mint)
    #[account(
        mut,
        constraint = merchant_token.owner == merchant_payout_wallet.key(),
        constraint = merchant_token.mint == mint.key()
    )]
    pub merchant_token: Account<'info, TokenAccount>,

    // ── DEST: Payer’s ATA (may not exist yet; we’ll create if missing) ─────
    /// CHECK: raw key only; must equal pi.payer
    pub payer_system: UncheckedAccount<'info>,

    /// Destination ATA = ATA(payer_system, mint); can be uninitialized
    /// CHECK: allow uninitialized; we’ll create if needed
    #[account(mut)]
    pub payer_token: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(reference: [u8; 32])]
pub struct AdminVoidPayment<'info> {
    // Read state to verify authority
    #[account(
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, State>,

    // Target payment intent (must be Pending)
    #[account(
        mut,
        seeds = [b"payment", merchant.key().as_ref(), &reference],
        bump
    )]
    pub payment_intent: Account<'info, PaymentIntent>,

    /// Used only for PDA derivation of payment_intent
    /// CHECK:
    pub merchant: UncheckedAccount<'info>,

    // Protocol authority (must match state.authority)
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(reference: [u8; 32])]
pub struct ClosePaymentIntent<'info> {
    // For authority check
    #[account(
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, State>,

    // Will be closed; rent goes to `closer`
    #[account(
        mut,
        close = closer,
        seeds = [b"payment", merchant.key().as_ref(), &reference],
        bump
    )]
    pub payment_intent: Account<'info, PaymentIntent>,

    /// Used only for PDA derivation of payment_intent
    /// CHECK:
    pub merchant: UncheckedAccount<'info>,

    // Recipient of reclaimed lamports; must sign and be authorized (payer or protocol authority)
    #[account(mut)]
    pub closer: Signer<'info>,
}

#[derive(Accounts)]
pub struct RotateMerchantAuthority<'info> {
    // Just to prove protocol is initialized; not used for auth
    #[account(
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, State>,

    // Existing merchant derived by old authority
    #[account(
        mut,
        seeds = [b"merchant", old_merchant_authority.key().as_ref()],
        bump = old_merchant.bump
    )]
    pub old_merchant: Account<'info, Merchant>,

    // New merchant PDA to be created with the new authority
    #[account(
        init,
        payer = payer,
        space = 8 + Merchant::INIT_SPACE,
        seeds = [b"merchant", new_merchant_authority.key().as_ref()],
        bump
    )]
    pub new_merchant: Account<'info, Merchant>,

    // Old authority must approve rotation
    pub old_merchant_authority: Signer<'info>,

    // New authority must consent (sign)
    pub new_merchant_authority: Signer<'info>,

    // Fee payer for creating the new merchant account (can be same as old authority)
    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetMintConfig<'info> {
    #[account(
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, State>,

    pub mint: Account<'info, Mint>,

    #[account(
        init,
        payer = authority,
        space = 8 + MintConfig::INIT_SPACE,
        seeds = [b"mint", mint.key().as_ref()],
        bump
    )]
    pub mint_config: Account<'info, MintConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(reference: [u8; 32])]
pub struct SettleSplWithFee<'info> {
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

    #[account(
        seeds = [b"merchant", merchant_authority.key().as_ref()],
        bump = merchant.bump
    )]
    pub merchant: Account<'info, Merchant>,

    /// CHECK: only for merchant PDA derivation
    pub merchant_authority: UncheckedAccount<'info>,

    pub mint: Account<'info, Mint>,

    // payer (signer) and their source ATA
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        mut,
        constraint = payer_token.owner == payer.key(),
        constraint = payer_token.mint == mint.key()
    )]
    pub payer_token: Account<'info, TokenAccount>,

    // merchant payout wallet (+ its ATA for this mint)
    /// CHECK:
    pub merchant_payout_wallet: UncheckedAccount<'info>,

    /// CHECK: allow uninitialized; we’ll create if needed
    #[account(mut)]
    pub merchant_token: UncheckedAccount<'info>,

    // mint config (whitelist + fee)
    #[account(
        seeds = [b"mint", mint.key().as_ref()],
        bump = mint_config.bump
    )]
    pub mint_config: Account<'info, MintConfig>,

    // treasury wallet (+ its ATA for this mint)
    /// CHECK:
    pub treasury_wallet: UncheckedAccount<'info>,

    /// CHECK: allow uninitialized; we’ll create if needed
    #[account(mut)]
    pub treasury_token: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,

    /// CHECK: sysvar instructions account (read-only)
    pub instructions: UncheckedAccount<'info>,

}


#[derive(Accounts)]
pub struct SetProtocolFeeDefaults<'info> {
    #[account(
        mut,
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, State>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(reference: [u8; 32])]
pub struct SettleSplWithDefaultFee<'info> {
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

    #[account(
        seeds = [b"merchant", merchant_authority.key().as_ref()],
        bump = merchant.bump
    )]
    pub merchant: Account<'info, Merchant>,

    /// CHECK:
    pub merchant_authority: UncheckedAccount<'info>,

    pub mint: Account<'info, Mint>,

    // payer signs + source ATA
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        mut,
        constraint = payer_token.owner == payer.key(),
        constraint = payer_token.mint == mint.key()
    )]
    pub payer_token: Account<'info, TokenAccount>,

    // merchant payout wallet + its ATA (create if missing)
    /// CHECK:
    pub merchant_payout_wallet: UncheckedAccount<'info>,

    /// CHECK:
    #[account(mut)]
    pub merchant_token: UncheckedAccount<'info>,

    // treasury (from state) + its ATA (create if missing)
    /// CHECK:
    pub treasury_wallet: UncheckedAccount<'info>,

    /// CHECK:
    #[account(mut)]
    pub treasury_token: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,

    /// CHECK: sysvar instructions account (read-only)
    pub instructions: UncheckedAccount<'info>,

}

#[derive(Accounts)]
pub struct CloseMerchant<'info> {
    // read state to allow protocol-admin close
    #[account(
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, State>,

    // Merchant PDA to be closed; rent lamports sent to `recipient`
    #[account(
        mut,
        close = recipient,
        seeds = [b"merchant", merchant_authority.key().as_ref()],
        bump = merchant.bump
    )]
    pub merchant: Account<'info, Merchant>,

    /// CHECK: used only for PDA derivation of `merchant`
    pub merchant_authority: UncheckedAccount<'info>,

    // Who receives the reclaimed rent.
    // Must be either the merchant.authority or the protocol state.authority (admin).
    #[account(mut)]
    pub recipient: Signer<'info>,
}




#[account]
#[derive(InitSpace)]
pub struct State {
   pub authority: Pubkey,
   pub bump: u8,
   pub treasury_default: Pubkey, 
   pub fee_bps_default: u16, 
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

fn assert_ed25519_present_for_message(
    instructions_ai: &AccountInfo,
    expected_signer: &Pubkey,
    message: &[u8],
) -> Result<()> {
    use anchor_lang::solana_program::program_memory::sol_memcmp;


    // Load the instructions sysvar and scan for an ed25519 verify
    let loader = sysvar_instructions::load_instruction_at_checked;
    let mut found = false;

    // A bounded scan: look at the first N instructions (adjust if you need more)
    // If you pack the verify as the immediately-previous ix, you can also just check `index - 1`.
    for i in 0..8 {
        if let Ok(ix) = loader(i, instructions_ai) {
            if ix.program_id == ed25519_program::id() {
                // Very lightweight check: ensure our `message` bytes appear in the ix data
                // and (optionally) the expected pubkey appears too. Real parsers decode the ed25519
                // verify layout; this keeps it simple and fast.
                if ix.data.windows(message.len()).any(|w| w == message) &&
                   ix.data.windows(32).any(|w| sol_memcmp(w, expected_signer.as_ref(), 32) == 0)
                {
                    found = true;
                    break;
                }
            }
        }
    }

    require!(found, ErrorCode::Unauthorized);
    Ok(())
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

#[account]
#[derive(InitSpace)]
pub struct MintConfig {
    pub mint: Pubkey,       
    pub allowed: u8,        
    pub fee_bps: u16,       
    pub treasury: Pubkey,    
    pub bump: u8,
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
    pub amount: u64,
    pub mint: Pubkey,
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


#[event]
pub struct PaymentRefunded {
    pub payment: Pubkey,
    pub payer: Pubkey,
    pub merchant: Pubkey,
    pub amount: u64,
    pub mint: Pubkey,
    pub reference: [u8; 32],
}

#[event]
pub struct PaymentVoided {
    pub payment: Pubkey,
    pub payer: Pubkey,
    pub merchant: Pubkey,
    pub reference: [u8; 32],
}

#[event]
pub struct PaymentClosed {
    pub payment: Pubkey,
    pub closer: Pubkey,
}

#[event]
pub struct MerchantAuthorityRotated {
    pub old_merchant: Pubkey,
    pub new_merchant: Pubkey,
    pub old_authority: Pubkey,
    pub new_authority: Pubkey,
}

#[event]
pub struct MintConfigUpdated {
    pub mint: Pubkey,
    pub allowed: u8,
    pub fee_bps: u16,
    pub treasury: Pubkey,
}

#[event]
pub struct ProtocolFeeDefaultsUpdated {
    pub treasury_default: Pubkey,
    pub fee_bps_default: u16,
}

#[event]
pub struct MerchantClosed {
    pub merchant: Pubkey,
    pub recipient: Pubkey,
}


