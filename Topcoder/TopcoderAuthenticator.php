<?php

namespace Vanilla\Authenticator;


/**
 * Class TopcoderAuthenticator
 */
class TopcoderAuthenticator extends ShimAuthenticator {

    /** @var TopcoderPlugin */
    private $topcoderPlugin;


    public function __construct(TopcoderPlugin $topcoderPlugin) {
        $this->topcoderPlugin = $topcoderPlugin;
        parent::__construct('topcoder');
    }

    /**
     * @inheritdoc
     */
    public static function isUnique(): bool {
        return true;
    }

    /**
     * @inheritDoc
     */
    protected static function getAuthenticatorTypeInfoImpl(): array {
        return [
            'ui' => [
                'photoUrl' => null,
                'backgroundColor' => null,
                'foregroundColor' => null,
            ]
        ];
    }

    /**
     * @inheritdoc
     */
    public function isActive(): bool {
        return $this->topcoderPlugin->isConfigured();
    }

}
