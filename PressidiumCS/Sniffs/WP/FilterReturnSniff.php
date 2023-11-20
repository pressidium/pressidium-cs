<?php
/**
 * Pressidium Coding Standards.
 */

namespace PressidiumCS\Sniffs\WP;

use PHP_CodeSniffer\Util\Tokens;
use WordPressCS\WordPress\Sniff;

/**
 * Flag WordPress filter callbacks without a return statement.
 * Heavily inspired by the `WordPress.WP.CronInterval` sniff.
 */
class FilterReturnSniff extends Sniff {

    /**
     * @var array Function within which the hook should be found.
     */
    protected $valid_functions = array(
        'add_filter' => true,
    );

    /**
     * Return an array of tokens this sniff wants to listen for.
     *
     * @return array
     */
    public function register() {
        return array(
            \T_CONSTANT_ENCAPSED_STRING,
            \T_DOUBLE_QUOTED_STRING,
        );
    }

    /**
     * Process this sniff, when one of its tokens is encountered.
     *
     * @param int $stackPtr The position of the current token in the stack.
     *
     * @return int|void Integer stack pointer to skip forward or void to continue
     *                  normal file processing.
     */
    public function process_token( $stackPtr ) {
        $token = $this->tokens[ $stackPtr ];

        // If within `add_filter`
        $functionPtr = $this->is_in_function_call( $stackPtr, $this->valid_functions );
        if ( $functionPtr === false ) {
            return;
        }

        $callback = $this->get_function_call_parameter( $functionPtr, 2 );
        if ( $callback === false ) {
            return;
        }

        // Detect callback function name
        $callbackArrayPtr = $this->phpcsFile->findNext( Tokens::$emptyTokens, $callback['start'], ( $callback['end'] + 1 ), true );

        // If callback is an array, get second element
        if ( $callbackArrayPtr !== false
             && ( \T_ARRAY === $this->tokens[ $callbackArrayPtr ]['code']
                  || \T_OPEN_SHORT_ARRAY === $this->tokens[ $callbackArrayPtr ]['code'] ) ) {
            $callback = $this->get_function_call_parameter( $callbackArrayPtr, 2 );

            if ( $callback === false ) {
                return;
            }
        }

        unset( $functionPtr );

        // Search for the function in tokens
        $callbackFunctionPtr = $this->phpcsFile->findNext(
            array( \T_CONSTANT_ENCAPSED_STRING, \T_DOUBLE_QUOTED_STRING, \T_CLOSURE ),
            $callback['start'],
            ( $callback['end'] + 1 )
        );

        if ( $callbackFunctionPtr === false ) {
            return;
        }

        if ( $this->tokens[ $callbackFunctionPtr ]['code'] === \T_CLOSURE ) {
            $functionPtr = $callbackFunctionPtr;
        } else {
            $functionName = $this->strip_quotes( $this->tokens[ $callbackFunctionPtr ]['content'] );

            for ( $ptr = 0; $ptr < $this->phpcsFile->numTokens; $ptr++ ) {
                if ( $this->tokens[ $ptr ]['code'] === \T_FUNCTION ) {
                    $foundName = $this->phpcsFile->getDeclarationName( $ptr );
                    if ( $foundName === $functionName ) {
                        $functionPtr = $ptr;
                        break;
                    } elseif ( isset( $this->tokens[ $ptr ]['scope_closer'] ) ) {
                        // Skip to the end of the function definition.
                        $ptr = $this->tokens[ $ptr ]['scope_closer'];
                    }
                }
            }
        }

        if ( ! isset( $functionPtr ) ) {
            return;
        }

        if ( ! isset( $this->tokens[ $functionPtr ]['scope_opener'], $this->tokens[ $functionPtr ]['scope_closer'] ) ) {
            return;
        }

        $opening = $this->tokens[ $functionPtr ]['scope_opener'];
        $closing = $this->tokens[ $functionPtr ]['scope_closer'];

        for ( $i = $opening; $i <= $closing; $i++ ) {
            if ( $this->tokens[ $i ]['code'] === \T_RETURN ) {
                return;
            }
        }

        $this->phpcsFile->addWarning(
            'Filter callback that does not return a value is discouraged.',
            $stackPtr,
            'MissingFilterReturn'
        );

        $this->phpcsFile->addWarning(
            'Filter callback that does not return a value is discouraged.',
            $functionPtr,
            'MissingFilterReturn'
        );
    }

}
