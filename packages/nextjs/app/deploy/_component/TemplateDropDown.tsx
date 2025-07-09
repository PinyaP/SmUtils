import { useState } from "react";
import React from "react";
import { ChevronDownIcon } from "@heroicons/react/24/solid";

type template = {
  id: number;
  ta: string;
  final: string;
  description: string;
};

export const TemplateDropDown = ({ onChange }: { onChange: (template: { ta: string; final: string }) => void }) => {
  const [selectedTemplate, setSelectedTemplate] = useState<template | null>(null);
  const [isOpen, setIsOpen] = useState(false);

  const templateContracts: template[] = [
    {
      id: 1,
      ta: ``,
      final: `// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/Strings.sol";

contract DayAndTime {

    struct HourAndMinute {
        uint256 hourInNum;
        uint256 minuteinNum;
    }

    function getDayOfWeek() private view returns (string memory) {
        string[7] memory dayArray = [
                                    "Sunday",
                                    "Monday",
                                    "Tuesday",
                                    "Wednesday",
                                    "Thursday",
                                    "Friday",
                                    "Saturday"
                                    ];
        
        uint256 dayIndex = (block.timestamp / 86400 + 4) % 7; // 86400 seconds in a day
        
        return dayArray[dayIndex];
    }

    function getTime() private view returns (HourAndMinute memory) {

        uint256 hourFromBlock = (block.timestamp / 3600) % 24;

        uint256 minuteFromBlock = (block.timestamp / 60) % 60;

        HourAndMinute memory returnResults = HourAndMinute(hourFromBlock, minuteFromBlock);

        return returnResults;
    }

    function toString(HourAndMinute memory _input, string memory _inputDay) private pure returns (string memory) {
        string memory returnText = string(
                                        abi.encodePacked(
                                            _inputDay,
                                            " at ",
                                            Strings.toString(_input.hourInNum),
                                            ":",
                                            Strings.toString(_input.minuteinNum),
                                            " (GMT+0)"));
        return returnText;
    }

    function getDayAndTime() public view returns (string memory) {
        return toString(getTime(), getDayOfWeek());
    }
    }`,
      description: "Day and Time.sol",
    },
    { id: 999, ta: ``, final: ``, description: "User Defined" },
  ];

  const handleSelectSm = (tm: template) => {
    setSelectedTemplate(tm);
    onChange({ ta: tm.ta, final: tm.final });
    setIsOpen(false);
  };

  return (
    <div className="relative w-1/2">
      <button
        className="bg-zinc-800 text-white border border-zinc-500 px-4 w-full rounded-lg h-12 flex items-center justify-between"
        onClick={() => setIsOpen(!isOpen)}
      >
        <span>{selectedTemplate ? `${selectedTemplate.description}` : "Select a Pre-set Contracts"}</span>
        <ChevronDownIcon className="w-4 h-4 ml-auto" />
      </button>
      {isOpen && (
        <ul className="absolute mt-2 bg-zinc-700 rounded-md w-full z-10">
          {templateContracts.map(tm => (
            <li key={tm.id} className="cursor-pointer px-4 py-2 hover:bg-zinc-500" onClick={() => handleSelectSm(tm)}>
              {tm.description}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};
