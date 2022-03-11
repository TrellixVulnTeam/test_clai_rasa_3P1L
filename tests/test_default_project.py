from typing import Any, Dict, Text

from warnings import WarningMessage
from _pytest.pytester import Testdir
import pytest
import copy

from rasa.__main__ import create_argument_parser
import rasa.cli.data
import rasa.cli.scaffold
import rasa.cli.train
import rasa.cli.shell
import rasa.shared.utils.io


def _warning_should_be_filtered_out(warning: WarningMessage) -> bool:
    # we filter out `gelu` warnings because of this issue:
    # https://github.com/RasaHQ/rasa/issues/9129
    # this function can be removed once we migrate to TensorFlow 2.6
    return type(warning.message) == DeprecationWarning and str(
        warning.message
    ).startswith("gelu activation has been migrated to core TensorFlow")


@pytest.mark.timeout(300, func_only=True)
def test_default_project_has_no_warnings(
    testdir: Testdir, default_config: Dict[Text, Any]
):
    parser = create_argument_parser()
    rasa.cli.scaffold.create_initial_project(".")

    config = copy.deepcopy(default_config)
    for model_part, items in config.items():
        for item in items:
            if "epochs" in item:
                item["epochs"] = 1
                item["evaluate_every_number_of_epochs"] = -1

    rasa.shared.utils.io.write_yaml(config, "config.yml")

    with pytest.warns(None) as warning_recorder:
        rasa.cli.data.validate_files(parser.parse_args(["data", "validate"]))
        rasa.cli.train.run_training(parser.parse_args(["train"]))

    assert not [
        w for w in warning_recorder._list if not _warning_should_be_filtered_out(w)
    ]
