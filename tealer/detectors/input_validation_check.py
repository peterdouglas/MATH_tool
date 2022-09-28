from pathlib import Path
from typing import List

from tealer.detectors.abstract_detector import AbstractDetector, DetectorType
from tealer.teal.basic_blocks import BasicBlock
from tealer.teal.instructions.transaction_field import AssetReceiver, XferAsset, TypeEnum
from tealer.teal.instructions.instructions import Return, Int, Gtxn, TransactionField, Instruction
from tealer.teal.teal import Teal


class Result:  # pylint: disable=too-few-public-methods
    def __init__(self, filename: Path, path_initial: List[BasicBlock], idx: int, gtxn_error: List[str]):
        self.filename = filename
        self.paths = [path_initial]
        self.idx = idx
        self.gtxn_error = gtxn_error

    @property
    def all_bbs_in_paths(self) -> List[BasicBlock]:
        return [p for sublist in self.paths for p in sublist]


class InputValidationCheck(AbstractDetector):  # pylint: disable=too-few-public-methods

    NAME = "inputValidationCheck"
    DESCRIPTION = "Detect asset transfers without an input validation check"
    TYPE = DetectorType.STATELESS

    def __init__(self, teal: Teal):
        super().__init__(teal)
        self.results_number = 0

    def _process_gtxn(
        self,
        gtxn_group: List[Instruction],
        ) -> bool:
        if len(gtxn_group) == 0:
            return

        has_xf_or_tenum = False
        has_AssetR = False

        for inst in gtxn_group:
            if isinstance(inst.field, AssetReceiver):
                has_AssetR = True
            if isinstance(inst.field, XferAsset) or isinstance(inst.field, TypeEnum):
                has_xf_or_tenum = True

        if has_AssetR and not has_xf_or_tenum:
            return False
        else:
            return True



    def _check_input(
        self,
        bb: BasicBlock,
        current_path: List[BasicBlock],
        # use_gtnx: bool,
        all_results: List[Result],
    ) -> None:
        # check for loops
        if bb in current_path:
            return

        current_path = current_path + [bb]
        gtxns = {
            0: [],
            1: [],
            2: [],
            3: [],
            4: [],
            5: [],
        }

        for ins in bb.instructions:
            if isinstance(ins, Gtxn):
                gtxns[ins.idx].append(ins)

        for key in gtxns:
            valid_group = self._process_gtxn(gtxns[key])

            if valid_group == False:
                gtxn_string = []
                for gt in gtxns[key]:
                    gtxn_string.append(f"{gt.line} | gtxn {gt.idx} {gt.field}")

                filename = Path(f"validation_check_{self.results_number}.dot")
                self.results_number += 1
                all_results.append(Result(filename, current_path, self.results_number, gtxn_string))

        for next_bb in bb.next:
            self._check_input(next_bb, current_path, all_results)

    def detect(self) -> List[str]:

        all_results: List[Result] = []
        self._check_input(self.teal.bbs[0], [], all_results)

        all_results_txt: List[str] = []
        for res in all_results:
            description = "Lack of input validation check found\n"
            description += f"\tCheck the transaction set below to see if additional checks need to be added\n"
            for li in res.gtxn_error:
                description += f"\t{li}\n"
            description += f"\tYou can find the paths in {res.filename}\n"

            all_results_txt.append(description)
            self.teal.bbs_to_dot(res.filename, res.all_bbs_in_paths)

        return all_results_txt
