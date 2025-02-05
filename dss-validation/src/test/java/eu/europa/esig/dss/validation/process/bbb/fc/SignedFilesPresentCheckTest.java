/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignedFilesPresentCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SignedFilesPresentCheckTest extends AbstractTestCheck {

	@Test
	void asicsValidTest() {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
		xmlContainerInfo.setContentFiles(Collections.singletonList("package.zip"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	void asicsNoFileTest() {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	void asicsMultipleFilesTest() {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
		xmlContainerInfo.setContentFiles(Arrays.asList("hello.xml", "world.xml"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	void asicsNotRootFileTest() {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
		xmlContainerInfo.setContentFiles(Collections.singletonList("hello/world.xml"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	void asicsMultipleFilesOneNotRootLevelTest() {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
		xmlContainerInfo.setContentFiles(Arrays.asList("hello.xml", "hello/world.xml"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	void asicsMultipleFilesBothNotRootLevelTest() {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
		xmlContainerInfo.setContentFiles(Arrays.asList("world/hello.xml", "hello/world.xml"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	void asiceValidTest() {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
		xmlContainerInfo.setContentFiles(Arrays.asList("hello.xml", "world.xml"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	void asiceOneFileTest() {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
		xmlContainerInfo.setContentFiles(Collections.singletonList("package.zip"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	void asiceNoFileTest() {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	void asiceNotRootFileTest() {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
		xmlContainerInfo.setContentFiles(Collections.singletonList("hello/world.xml"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

}
