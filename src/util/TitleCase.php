<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

# TODO: finish this

final class TitleCase {

    public static String toTitleCase(String input) {
        final StringBuilder titleCase = new StringBuilder(input.length());
        boolean nextTitleCase = true;

        for (char c : input.toLowerCase().toCharArray()) {
            if (!Character.isLetterOrDigit(c)) {
                nextTitleCase = true;
            } else if (nextTitleCase) {
                c = Character.toTitleCase(c);
                nextTitleCase = false;
            }
            titleCase.append(c);
        }

        return titleCase.toString();
    }

	public function __construct()
	{
		throw new IllegalStateException("Utility class");
	}
}
